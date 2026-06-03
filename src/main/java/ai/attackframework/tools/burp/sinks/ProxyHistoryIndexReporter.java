package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.concurrent.EdtMonitor;
import ai.attackframework.tools.burp.utils.concurrent.LazyScheduler;
import ai.attackframework.tools.burp.utils.concurrent.SnapshotPacing;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

/**
 * Pushes Proxy History items to the traffic index once when Start is clicked and
 * "Proxy History" is selected. Runs in the background in batches; no recurring push.
 * For ongoing traffic after that, use Proxy. Respects scope (All / Burp / Custom).
 */
public final class ProxyHistoryIndexReporter {

    private static final String SCHEMA_VERSION = "1";
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024;
    private static final int SNAPSHOT_BATCH_INITIAL = 250;
    private static final int SNAPSHOT_BATCH_MIN = 100;
    private static final int SNAPSHOT_BATCH_MAX = 1500;
    private static final int LIVE_QUEUE_BACKPRESSURE_DOCS = 10_000;
    private static final int LIVE_SPILL_BACKPRESSURE_DOCS = 2_000;
    private static final long BACKPRESSURE_PAUSE_MS = 75;

    /**
     * Single-owner scheduler for proxy-history snapshot work.
     *
     * <p>Created lazily by {@link LazyScheduler#getOrStart()} the first time a snapshot is
     * scheduled and torn down deterministically by {@link #stop()} during UI stop or extension
     * unload. Matches the lazy/stop pattern used by every other reporter in this package.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("attackframework-proxy-history-scheduler");

    private ProxyHistoryIndexReporter() {}

    /**
     * Stops the proxy-history scheduler so the extension unloads cleanly.
     *
     * <p>Safe to call from any thread and safe to call more than once. A subsequent
     * {@link #pushSnapshotNow()} lazily starts a fresh scheduler via {@link LazyScheduler}.</p>
     */
    public static void stop() {
        SCHEDULER.stop();
    }

    /**
     * Schedules a one-time push of all current proxy history items (on Start), after a short delay.
     *
     * <p>Safe to call from any thread; work runs on a background thread. No-op if export is not
     * running, no sink is enabled, or PROXY_HISTORY is not selected.</p>
     */
    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnyTrafficExportEnabled()) {
                return;
            }
            List<String> trafficTypes = RuntimeConfig.getState().trafficToolTypes();
            if (trafficTypes == null || !trafficTypes.contains("proxy_history")) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null || api.proxy() == null) {
                return;
            }
            MontoyaApi apiRef = api;
            SCHEDULER.getOrStart().execute(() -> {
                if (!RuntimeConfig.isExportRunning()) return;
                String activeBaseUrl = RuntimeConfig.openSearchUrl();
                pushItems(apiRef, activeBaseUrl);
            });
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[Traffic] Proxy history snapshot push failed: " + msg);
        }
    }

    /**
     * Pushes proxy-history items using bounded, streaming chunks.
     *
     * <p>Runs only on the reporter scheduler thread. This method avoids building the full
     * history payload in memory by flushing chunks when either doc-count or estimated payload
     * size thresholds are reached.</p>
     *
     * @param api Burp API reference
     * @param baseUrl OpenSearch base URL
     */
    private static void pushItems(MontoyaApi api, String baseUrl) {
        boolean openSearchActive = RuntimeConfig.isOpenSearchActive();
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (history == null || history.isEmpty()) {
            return;
        }

        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyHistorySnapshot();
        SnapshotSummary.Baseline baseline = SnapshotSummary.forRoute(route);
        long startNs = System.nanoTime();
        int success = 0;
        int attempted = 0;
        int chunkTarget = initialSnapshotBatchSize();
        long estBytes = 0;
        List<Map<String, Object>> chunk = new ArrayList<>(chunkTarget);

        // Run-scoped diagnostics. Every chunk log line embeds a worker-side wall-clock
        // ({@code wt=}) so EDT-side log delivery lag can be measured against ground truth, and
        // {@link EdtMonitor} captures stack traces whenever the EDT misses its tick deadline.
        // Together these let post-incident log review distinguish "snapshot thread is slow"
        // from "snapshot thread is fine but the EDT is blocked".
        SnapshotPacing.resetCountersForSnapshot();
        EdtMonitor.start();
        try {
        long startGcMs = totalGcCollectionTimeMs();
        long lastChunkGcMs = startGcMs;
        long lastChunkWallMs = System.currentTimeMillis();
        int chunkSeq = 0;
        Logger.logInfoPanelOnly("[ProxyHistory.snapshot] start: wt=" + nowWallClock()
                + " items=" + history.size()
                + " initial_chunk_target=" + chunkTarget
                + " heap_used_mib=" + heapUsedMib()
                + " gc_time_ms=" + startGcMs);

        int processed = 0;
        for (ProxyHttpRequestResponse item : history) {
            if (!RuntimeConfig.isExportRunning()) {
                break;
            }
            // Cooperative pacing: brief yield + GC duty-cycle gate every Nth iteration so the
            // snapshot loop never starves the EDT or saturates G1's concurrent threads on
            // multi-tens-of-thousands-of-item projects.
            SnapshotPacing.paceItem(processed);
            processed++;
            Map<String, Object> doc = buildDocument(api, item);
            if (doc == null) {
                continue;
            }
            long docBytes = BulkPayloadEstimator.estimateBytes(doc);
            boolean sizeCapReached = !chunk.isEmpty() && (estBytes + docBytes) > BULK_MAX_BYTES;
            boolean countCapReached = !chunk.isEmpty() && chunk.size() >= chunkTarget;
            if (sizeCapReached || countCapReached) {
                chunkTarget = applyLiveBackpressure(chunkTarget);
                int attemptedChunk = chunk.size();
                long preBytes = estBytes;
                int sent = OpenSearchClientWrapper.pushBulk(
                        baseUrl, TrafficRouteBucket.trafficIndexName(), TrafficRouteBucket.INDEX_KEY, chunk);
                success += sent;
                attempted += attemptedChunk;
                recordChunkOutcome(route, openSearchActive, attemptedChunk, sent);
                chunkTarget = adjustSnapshotBatchTarget(chunkTarget, attemptedChunk, sent);
                chunkSeq++;
                long nowMs = System.currentTimeMillis();
                long curGcMs = totalGcCollectionTimeMs();
                logChunkProgress(
                        chunkSeq,
                        attemptedChunk,
                        sent,
                        preBytes,
                        nowMs - lastChunkWallMs,
                        chunkTarget,
                        curGcMs - lastChunkGcMs,
                        processed,
                        history.size());
                lastChunkWallMs = nowMs;
                lastChunkGcMs = curGcMs;
                chunk.clear();
                estBytes = 0;
            }
            chunk.add(doc);
            estBytes += docBytes;
        }
        if (RuntimeConfig.isExportRunning() && !chunk.isEmpty()) {
            chunkTarget = applyLiveBackpressure(chunkTarget);
            int attemptedChunk = chunk.size();
            long preBytes = estBytes;
            int sent = OpenSearchClientWrapper.pushBulk(
                    baseUrl, TrafficRouteBucket.trafficIndexName(), TrafficRouteBucket.INDEX_KEY, chunk);
            success += sent;
            attempted += attemptedChunk;
            recordChunkOutcome(route, openSearchActive, attemptedChunk, sent);
            chunkSeq++;
            long nowMs = System.currentTimeMillis();
            long curGcMs = totalGcCollectionTimeMs();
            logChunkProgress(
                    chunkSeq,
                    attemptedChunk,
                    sent,
                    preBytes,
                    nowMs - lastChunkWallMs,
                    chunkTarget,
                    curGcMs - lastChunkGcMs,
                    processed,
                    history.size());
        }

        long durationMs = (System.nanoTime() - startNs) / 1_000_000;
        if (openSearchActive) {
            ExportStats.recordLastPush(TrafficRouteBucket.INDEX_KEY, durationMs);
        }
        ExportStats.recordProxyHistorySnapshot(attempted, success, durationMs, chunkTarget);
        Logger.logInfoPanelOnly(SnapshotPacing.summaryLine("ProxyHistory")
                + " wt=" + nowWallClock()
                + " elapsed_ms=" + durationMs
                + " chunks=" + chunkSeq);
        SnapshotSummary.logInfo(
                "ProxyHistory",
                baseline,
                attempted,
                durationMs,
                openSearchActive,
                RuntimeConfig.isAnyFileExportEnabled());
        } finally {
            EdtMonitor.stop();
        }
    }

    /**
     * Emits a single-line per-chunk progress record for after-the-fact snapshot timeline review.
     *
     * <p>Each line carries the JMX GC-time delta accumulated since the previous chunk push, so a
     * reader can see exactly which chunks coincided with stop-the-world pressure. The worker-side
     * {@code wt=} timestamp lets readers correlate against the {@code [yyyy-MM-dd HH:mm:ss]} EDT
     * render prefix and detect log-delivery lag during EDT stalls.</p>
     */
    private static void logChunkProgress(
            int chunkSeq,
            int attemptedChunk,
            int sent,
            long estBytes,
            long sinceLastChunkMs,
            int chunkTarget,
            long gcDeltaMs,
            int processed,
            int total) {
        Logger.logInfoPanelOnly("[ProxyHistory.chunk] wt=" + nowWallClock()
                + " seq=" + chunkSeq
                + " items=" + attemptedChunk
                + " sent=" + sent
                + " est_bytes=" + estBytes
                + " elapsed_ms=" + sinceLastChunkMs
                + " chunk_target=" + chunkTarget
                + " heap_used_mib=" + heapUsedMib()
                + " gc_time_delta_ms=" + gcDeltaMs
                + " duty_per_mille=" + SnapshotPacing.lastDutyPerMille()
                + " gate_trips_total=" + SnapshotPacing.gateTripCount()
                + " progress=" + processed + "/" + total);
    }

    /**
     * Returns a worker-side wall-clock timestamp ({@code HH:mm:ss.SSS}) captured on the calling
     * thread. Embedded into every diagnostic log line so we can compute the EDT delivery lag by
     * comparing this value with the {@code [yyyy-MM-dd HH:mm:ss]} prefix that the LogPanel
     * appends when it renders the entry on the EDT.
     */
    private static String nowWallClock() {
        return EdtMonitor.WallClock.format(System.currentTimeMillis());
    }

    private static long totalGcCollectionTimeMs() {
        long sum = 0L;
        try {
            for (var bean : java.lang.management.ManagementFactory.getGarbageCollectorMXBeans()) {
                long t = bean.getCollectionTime();
                if (t > 0L) {
                    sum += t;
                }
            }
        } catch (RuntimeException ignored) {
            // Fall through with whatever we accumulated.
        }
        return sum;
    }

    private static long heapUsedMib() {
        Runtime rt = Runtime.getRuntime();
        long bytes = rt.totalMemory() - rt.freeMemory();
        return bytes / (1024L * 1024L);
    }

    private static void recordChunkOutcome(
            TrafficRouteBucket.Route route,
            boolean openSearchActive,
            int attemptedChunk,
            int sent) {
        TrafficRouteBucket.recordBulkOutcome(route, attemptedChunk, sent, openSearchActive, "Proxy history chunk");
    }

    /**
     * Chooses the initial proxy-history chunk target using shared runtime observations.
     *
     * <p>When the shared controller already converged above baseline, we reuse that value as a
     * lower bound so history backfill does not start at an unnecessarily small chunk size.</p>
     *
     * @return initial doc-count target for history chunks
     */
    private static int initialSnapshotBatchSize() {
        int shared = BatchSizeController.getInstance().getCurrentBatchSize();
        int base = Math.max(SNAPSHOT_BATCH_INITIAL, shared);
        return Math.min(SNAPSHOT_BATCH_MAX, Math.max(SNAPSHOT_BATCH_MIN, base));
    }

    /**
     * Adjusts proxy-history chunk target from observed bulk outcome.
     *
     * <p>On full success, grows quickly to improve history-drain throughput. On partial/full
     * failures, shrinks conservatively to reduce pressure on cluster and queueing paths.</p>
     *
     * @param current current target doc count
     * @param attempted docs attempted in the last chunk
     * @param succeeded docs acknowledged successful in the last chunk
     * @return next target doc count
     */
    private static int adjustSnapshotBatchTarget(int current, int attempted, int succeeded) {
        if (attempted <= 0) {
            return current;
        }
        if (succeeded >= attempted) {
            int grow = Math.max(25, current / 4);
            return Math.min(SNAPSHOT_BATCH_MAX, current + grow);
        }
        int reduced = Math.max(SNAPSHOT_BATCH_MIN, current / 2);
        return Math.min(reduced, Math.max(SNAPSHOT_BATCH_MIN, succeeded));
    }

    /**
     * Engages chunk-level backpressure when either the live traffic queue is deep or the JVM is
     * GC-saturated, halving the chunk doc-count target when either signal trips.
     *
     * <p>Queue-depth alone is not sufficient on large histories: synchronous bulk pushes keep the
     * live queue near zero during a snapshot, so a 26k+-item history can thrash G1 without ever
     * crossing the queue-depth threshold. The {@link SnapshotPacing#gcSaturated()} signal covers
     * that case by reducing the chunk target when GC duty cycle is the dominant pressure.</p>
     *
     * @param currentTarget current chunk doc-count target
     * @return possibly reduced target (halved when backpressure trips)
     */
    private static int applyLiveBackpressure(int currentTarget) {
        int liveQueueDocs = TrafficExportQueue.getCurrentSize();
        int spillDocs = TrafficExportQueue.getCurrentSpillSize();
        boolean queuePressure = liveQueueDocs >= LIVE_QUEUE_BACKPRESSURE_DOCS
                || spillDocs >= LIVE_SPILL_BACKPRESSURE_DOCS;
        boolean gcPressure = SnapshotPacing.gcSaturated();
        if (!queuePressure && !gcPressure) {
            return currentTarget;
        }
        try {
            Thread.sleep(BACKPRESSURE_PAUSE_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Math.max(SNAPSHOT_BATCH_MIN, currentTarget / 2);
        }
        return Math.max(SNAPSHOT_BATCH_MIN, currentTarget / 2);
    }

    private static Map<String, Object> buildDocument(MontoyaApi api, ProxyHttpRequestResponse item) {
        HttpRequest request = item.finalRequest();
        if (request == null) {
            return null;
        }
        HttpService service = item.httpService();
        String scheme = service == null ? null : (service.secure() ? "https" : "http");
        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        String url = RequestResponseDocBuilder.buildBestEffortUrl(request, service, requestDoc, "ProxyHistory");
        boolean burpInScope = url != null && api.scope().isInScope(url);
        requestDoc.put("url", url);
        requestDoc.put("port", service == null ? null : service.port());
        requestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                scheme, RequestResponseDocBuilder.safeRequestHttpVersion(request)));

        Map<String, Object> document = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", "Proxy History");
        burp.put("is_in_scope", burpInScope);
        burp.put("message_id", item.id());
        burp.put("proxy", BurpProxyFields.forProxyHistory(item));
        burp.put("timing", BurpTimingFields.fromProxyHistory(item));
        BurpAnnotationFields.put(burp, item.annotations());
        document.put("burp", burp);
        document.put("request", requestDoc);

        HttpResponse response = item.response();
        if (response != null) {
            document.put("response", RequestResponseDocBuilder.buildTrafficResponseDoc(response));
        } else {
            document.put("response", RequestResponseDocBuilder.emptyTrafficResponseDoc());
        }
        document.put("websocket", WebSocketTrafficDocumentBuilder.notWebSocket());

        document.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));

        // HTTP docs from Proxy History are not websocket messages.
        return document;
    }
}
