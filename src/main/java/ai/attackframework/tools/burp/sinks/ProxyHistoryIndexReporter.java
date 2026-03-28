package ai.attackframework.tools.burp.sinks;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
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

    private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "attackframework-proxy-history-scheduler");
        t.setDaemon(true);
        return t;
    });

    private ProxyHistoryIndexReporter() {}

    private static String trafficIndexName() {
        return IndexNaming.indexNameForShortName("traffic");
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
            if (!RuntimeConfig.isOpenSearchTrafficEnabled()) {
                return;
            }
            List<String> trafficTypes = RuntimeConfig.getState().trafficToolTypes();
            if (trafficTypes == null || !trafficTypes.contains("PROXY_HISTORY")) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null || api.proxy() == null) {
                return;
            }
            MontoyaApi apiRef = api;
            scheduler.execute(() -> {
                if (!RuntimeConfig.isExportRunning()) return;
                String activeBaseUrl = RuntimeConfig.openSearchUrl();
                pushItems(apiRef, activeBaseUrl);
            });
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logDebug("Proxy History index: push failed: " + msg);
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
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (history == null || history.isEmpty()) {
            return;
        }

        long startNs = System.nanoTime();
        int success = 0;
        int attempted = 0;
        int chunkTarget = initialSnapshotBatchSize();
        long estBytes = 0;
        List<Map<String, Object>> chunk = new ArrayList<>(chunkTarget);

        for (ProxyHttpRequestResponse item : history) {
            if (!RuntimeConfig.isExportRunning()) {
                break;
            }
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
                int sent = OpenSearchClientWrapper.pushBulk(baseUrl, trafficIndexName(), chunk);
                success += sent;
                attempted += attemptedChunk;
                ExportStats.recordSuccess("traffic", sent);
                ExportStats.recordTrafficSourceSuccess("proxy_history_snapshot", sent);
                if (sent < attemptedChunk) {
                    int failureChunk = attemptedChunk - sent;
                    ExportStats.recordFailure("traffic", failureChunk);
                    ExportStats.recordTrafficSourceFailure("proxy_history_snapshot", failureChunk);
                }
                chunkTarget = adjustSnapshotBatchTarget(chunkTarget, attemptedChunk, sent);
                chunk.clear();
                estBytes = 0;
            }
            chunk.add(doc);
            estBytes += docBytes;
        }
        if (RuntimeConfig.isExportRunning() && !chunk.isEmpty()) {
            chunkTarget = applyLiveBackpressure(chunkTarget);
            int attemptedChunk = chunk.size();
            int sent = OpenSearchClientWrapper.pushBulk(baseUrl, trafficIndexName(), chunk);
            success += sent;
            attempted += attemptedChunk;
            ExportStats.recordSuccess("traffic", sent);
            ExportStats.recordTrafficSourceSuccess("proxy_history_snapshot", sent);
            if (sent < attemptedChunk) {
                int failureChunk = attemptedChunk - sent;
                ExportStats.recordFailure("traffic", failureChunk);
                ExportStats.recordTrafficSourceFailure("proxy_history_snapshot", failureChunk);
            }
        }

        long durationMs = (System.nanoTime() - startNs) / 1_000_000;
        ExportStats.recordLastPush("traffic", durationMs);
        ExportStats.recordProxyHistorySnapshot(attempted, success, durationMs, chunkTarget);
        Logger.logTrace("[ProxyHistory] pushed " + success + " of " + attempted);
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

    private static int applyLiveBackpressure(int currentTarget) {
        int liveQueueDocs = TrafficExportQueue.getCurrentSize();
        int spillDocs = TrafficExportQueue.getCurrentSpillSize();
        if (liveQueueDocs < LIVE_QUEUE_BACKPRESSURE_DOCS && spillDocs < LIVE_SPILL_BACKPRESSURE_DOCS) {
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
        String url = request.url();
        boolean burpInScope = url != null && api.scope().isInScope(url);

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", request.url());
        document.put("host", service == null ? null : service.host());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", scheme);
        document.put("protocol_transport", scheme);
        document.put("protocol_application", "http");
        document.put("protocol_sub", request.httpVersion());
        document.put("http_version", request.httpVersion());
        document.put("tool", "Proxy History");
        document.put("tool_type", "PROXY_HISTORY");
        document.put("burp_in_scope", burpInScope);
        document.put("message_id", item.id());
        document.put("proxy_history_id", item.id());
        document.put("listener_port", item.listenerPort());
        document.put("edited", item.edited());
        populateTiming(document, item);
        putAnnotations(document, item.annotations());
        document.put("path", request.path());
        document.put("method", request.method());
        document.put("request", RequestResponseDocBuilder.buildRequestDoc(request));

        HttpResponse response = item.response();
        if (response != null) {
            document.put("status", (int) response.statusCode());
            document.put("mime_type", response.mimeType() == null ? null : response.mimeType().name());
            document.put("response", RequestResponseDocBuilder.buildResponseDoc(response));
        } else {
            document.put("status", 0);
            document.put("mime_type", (String) null);
            document.put("response", emptyResponseDoc());
        }

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        meta.put("indexed_at", Instant.now().toString());
        document.put("document_meta", meta);

        // HTTP docs from Proxy History are not websocket messages.
        document.put("websocket_id", null);
        document.put("ws_direction", null);
        document.put("ws_message_type", null);
        document.put("ws_payload", null);
        document.put("ws_payload_text", null);
        document.put("ws_payload_length", null);
        document.put("ws_edited", null);
        document.put("ws_edited_payload", null);
        document.put("ws_upgrade_request", null);
        document.put("ws_time", null);
        document.put("ws_message_id", null);

        return document;
    }

    private static void populateTiming(Map<String, Object> document, ProxyHttpRequestResponse item) {
        String timeRequestSent = null;
        Integer responseStartLatencyMs = null;
        Integer durationMs = null;
        String timeEnd = null;
        try {
            TimingData td = item.timingData();
            if (td != null) {
                ZonedDateTime sent = td.timeRequestSent();
                if (sent != null) {
                    timeRequestSent = sent.toInstant().toString();
                }
                var start = td.timeBetweenRequestSentAndStartOfResponse();
                if (start != null) {
                    responseStartLatencyMs = (int) start.toMillis();
                }
                var end = td.timeBetweenRequestSentAndEndOfResponse();
                if (end != null) {
                    durationMs = (int) end.toMillis();
                    if (sent != null) {
                        timeEnd = sent.plus(end).toInstant().toString();
                    }
                }
            }
        } catch (Exception ignored) {
            // optional timing fields
        }
        if (timeRequestSent == null) {
            try {
                ZonedDateTime t = item.time();
                if (t != null) {
                    timeRequestSent = t.toInstant().toString();
                }
            } catch (Exception ignored) {
                // keep null
            }
        }
        document.put("time_request_sent", timeRequestSent);
        document.put("time_start", timeRequestSent);
        document.put("time_end", timeEnd);
        document.put("response_start_latency_ms", responseStartLatencyMs);
        document.put("duration_ms", durationMs);
    }

    private static void putAnnotations(Map<String, Object> document, burp.api.montoya.core.Annotations annotations) {
        if (annotations == null) {
            return;
        }
        if (annotations.hasNotes()) {
            document.put("comment", annotations.notes());
        }
        if (annotations.hasHighlightColor()) {
            var color = annotations.highlightColor();
            document.put("highlight", color == null ? null : color.name());
        }
    }

    private static Map<String, Object> emptyResponseDoc() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 0);
        m.put("status_code_class", null);
        m.put("reason_phrase", "No response");
        m.put("http_version", null);
        m.put("headers", List.of());
        m.put("cookies", List.of());
        m.put("mime_type", null);
        m.put("stated_mime_type", null);
        m.put("inferred_mime_type", null);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("b64", null);
        body.put("text", null);
        m.put("body", body);
        m.put("body_length", 0);
        m.put("body_offset", 0);
        m.put("markers", List.of());
        m.put("header_names", List.of());
        return m;
    }
}
