package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.concurrent.LazyScheduler;
import ai.attackframework.tools.burp.utils.concurrent.SnapshotExportEngine;
import ai.attackframework.tools.burp.utils.concurrent.SnapshotPacing;
import ai.attackframework.tools.burp.utils.concurrent.SnapshotScopeCache;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.ExportDocumentIdentity;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Pushes Burp sitemap items to the sitemap index when export is running and
 * "Sitemap" is selected. Initial push on Start (background); every 30 seconds
 * exports only new sitemap rows (in-memory seen keys). Does not start a new
 * run while the previous is still in progress. Respects extension scope (All / Burp / Custom).
 */
public final class SitemapIndexReporter {

    private static final int INTERVAL_SECONDS = 30;
    /** Flush when batch exceeds this approximate payload size (bytes) so large bodies don't produce huge bulk requests. */
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024; // 5 MB
    private static final String SCHEMA_VERSION = "1";

    /**
     * Single-owner scheduler for sitemap snapshot and recurring pushes.
     *
     * <p>Created lazily by {@link LazyScheduler#getOrStart()} on {@link #start()} and torn down
     * by {@link #stop()} during UI stop or extension unload. A subsequent {@link #start()} or
     * {@link #pushSnapshotNow()} lazily recreates the executor.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("attackframework-sitemap-reporter");
    private static final PeriodicExportSeenKeys PERIODIC_EXPORT_SEEN_KEYS =
            new PeriodicExportSeenKeys();
    private static volatile boolean runInProgress;

    private SitemapIndexReporter() {}

    private static String sitemapIndexName() {
        return RuntimeConfig.indexNameForKey("sitemap");
    }

    /**
     * Pushes all current sitemap items once (e.g. initial push on Start). Safe to call
     * from any thread. Schedules work on the reporter thread and returns immediately so
     * the UI does not freeze. No-op if export is not running, no sink is enabled,
     * or Sitemap is not in the selected data sources.
     */
    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            List<String> sources = RuntimeConfig.getState().dataSources();
            if (sources == null || !sources.contains(ConfigKeys.SRC_SITEMAP)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            ScheduledExecutorService exec = SCHEDULER.peek();
            if (exec != null) {
                exec.submit(() -> {
                    try {
                        pushItems(api, true);
                    } catch (Throwable ignored) {
                        // Startup/lifecycle races in Burp can transiently null sub-APIs.
                    }
                });
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[SnapshotExport] Sitemap: push failed: " + msg);
        }
    }

    /**
     * Starts the 30-second scheduler. Does not perform an initial push (caller
     * must call {@link #pushSnapshotNow()} once on Start). Safe to call from any thread.
     */
    public static void start() {
        SCHEDULER.startRecurring(
                SitemapIndexReporter::pushNewItemsOnly,
                INTERVAL_SECONDS,
                INTERVAL_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * Stops the periodic scheduler and clears per-session reporter state.
     *
     * <p>Safe to call from any thread. The next {@link #start()} call creates a fresh scheduler.</p>
     */
    public static void stop() {
        SCHEDULER.stop();
        runInProgress = false;
        PERIODIC_EXPORT_SEEN_KEYS.clear();
    }

    static void pushNewItemsOnly() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            List<String> sources = RuntimeConfig.getState().dataSources();
            if (sources == null || !sources.contains(ConfigKeys.SRC_SITEMAP)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            pushItems(api, false);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[PeriodicExport] Sitemap: push failed: " + msg);
        }
    }

    private record SitemapWorkItem(HttpRequestResponse item, boolean burpInScope) {
    }

    private static void pushItems(MontoyaApi api, boolean pushAll) {
        if (runInProgress) {
            return;
        }
        runInProgress = true;
        try {
            List<HttpRequestResponse> items = safeSiteMapItems(api);
            if (items == null) {
                return;
            }
            if (pushAll) {
                pushAllItemsParallel(api, items);
            } else {
                pushIncrementalItems(api, items);
            }
        } finally {
            runInProgress = false;
        }
    }

    private static void pushAllItemsParallel(MontoyaApi api, List<HttpRequestResponse> items) {
        var state = RuntimeConfig.getState();
        SnapshotScopeCache scopeCache = new SnapshotScopeCache(api);
        Set<String> startupKeys = ConcurrentHashMap.newKeySet();
        AtomicInteger processed = new AtomicInteger();
        AtomicInteger skippedScope = new AtomicInteger();
        AtomicInteger skippedDuplicate = new AtomicInteger();
        boolean openSearchActive = RuntimeConfig.isOpenSearchActive();
        boolean fileActive = RuntimeConfig.isAnyFileExportEnabled();
        SnapshotSummary.Baseline baseline = SnapshotSummary.forIndexKey("sitemap");
        long startNs = System.nanoTime();
        String indexName = sitemapIndexName();
        String activeBaseUrl = RuntimeConfig.openSearchUrl();
        int batchSize = SnapshotBatchTuning.initialTarget();
        Logger.logInfoPanelOnly("[StartupExport] Sitemap: exporting backlog: " + items.size() + " item(s).");
        SnapshotPacing.resetCountersForSnapshot();

        SnapshotExportEngine.Result exportResult = SnapshotExportEngine.run(
                items,
                SnapshotExportEngine.defaultBuildWorkers(),
                BULK_MAX_BYTES,
                batchSize,
                SnapshotBatchTuning::applyLiveBackpressure,
                SnapshotBatchTuning.chunkTargetAdjuster(),
                activeBaseUrl,
                indexName,
                "sitemap",
                item -> {
                    SitemapWorkItem work = toStartupWorkItem(
                            item, state, scopeCache, startupKeys, processed, skippedScope, skippedDuplicate);
                    if (work == null) {
                        return null;
                    }
                    return prepareSitemapWorkItem(indexName, work);
                },
                (chunk, outcome, nextChunkTarget) ->
                        BulkOutcomeRecorder.record(
                                "sitemap", "Sitemap", "Bulk push", outcome, openSearchActive));

        long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
        ExportStats.recordSnapshotLastRun(
                ExportStats.SNAPSHOT_SITEMAP,
                exportResult.attempted(),
                exportResult.success(),
                durationMs,
                exportResult.finalChunkTarget(),
                exportResult.chunks(),
                exportResult.totalChunkBytes(),
                exportResult.buildWallMs(),
                exportResult.buildCpuMs(),
                exportResult.flushMs(),
                exportResult.fileFlushMs(),
                exportResult.openSearchFlushMs(),
                exportResult.buildWorkers());
        SnapshotSummary.logInfo(
                "Sitemap",
                baseline,
                exportResult.attempted(),
                durationMs,
                exportResult.buildWallMs(),
                exportResult.flushMs(),
                openSearchActive,
                fileActive);
        Logger.logInfoPanelOnly("[SnapshotExport] Sitemap: backlog filters: seen=" + items.size()
                + " exported=" + exportResult.attempted()
                + " skipped_scope=" + skippedScope.get()
                + " skipped_duplicate=" + skippedDuplicate.get()
                + " in " + durationMs + "ms.");
    }

    private static SitemapWorkItem toStartupWorkItem(
            HttpRequestResponse item,
            ConfigState.State state,
            SnapshotScopeCache scopeCache,
            Set<String> startupKeys,
            AtomicInteger processed,
            AtomicInteger skippedScope,
            AtomicInteger skippedDuplicate) {
        SnapshotPacing.paceItem(processed.getAndIncrement());
        if (item == null) {
            return null;
        }
        HttpRequest request = item.request();
        if (request == null) {
            return null;
        }
        String url = RequestResponseDocBuilder.safeRequestUrl(request, "Sitemap");
        if (url == null) {
            url = "";
        }
        boolean burpInScope = scopeCache.isInScope(url);
        if (!ScopeFilter.shouldExport(state, url, burpInScope)) {
            skippedScope.incrementAndGet();
            return null;
        }
        String itemKey = SnapshotExportFingerprints.sitemapItemKey(request);
        if (!startupKeys.add(itemKey)) {
            skippedDuplicate.incrementAndGet();
            return null;
        }
        PERIODIC_EXPORT_SEEN_KEYS.recordSeen(itemKey);
        return new SitemapWorkItem(item, burpInScope);
    }

    private static PreparedExportDocument prepareSitemapWorkItem(String indexName, SitemapWorkItem work) {
        Map<String, Object> doc = buildSitemapDoc(work.item(), work.burpInScope());
        if (doc == null) {
            return null;
        }
        return ExportDocumentIdentity.prepare(indexName, "sitemap", doc);
    }

    private static void pushIncrementalItems(MontoyaApi api, List<HttpRequestResponse> items) {
        var state = RuntimeConfig.getState();
        SnapshotScopeCache scopeCache = new SnapshotScopeCache(api);
        int batchTarget = BatchSizeController.getInstance().getCurrentBatchSize();
        List<PreparedExportDocument> batchDocs = new ArrayList<>(batchTarget);
        long runningBatchBytes = 0;
        String indexName = sitemapIndexName();
        int processed = 0;
        int checked = 0;
        int exported = 0;

        for (HttpRequestResponse item : items) {
            if (!RuntimeConfig.isExportRunning()) {
                break;
            }
            SnapshotPacing.paceItem(processed);
            processed++;
            SitemapWorkItem work = toWorkItem(item, state, scopeCache);
            if (work == null) {
                continue;
            }
            checked++;
            String itemKey = SnapshotExportFingerprints.sitemapItemKey(work.item().request());
            if (!PERIODIC_EXPORT_SEEN_KEYS.isNew(itemKey)) {
                continue;
            }
            Map<String, Object> doc = buildSitemapDoc(work.item(), work.burpInScope());
            if (doc == null) {
                continue;
            }
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, "sitemap", doc);
            if (!PERIODIC_EXPORT_SEEN_KEYS.claimNew(itemKey)) {
                continue;
            }
            batchDocs.add(prepared);
            runningBatchBytes += prepared.estimatedBulkBytes();
            exported++;

            if (batchDocs.size() >= batchTarget || runningBatchBytes >= BULK_MAX_BYTES) {
                flushBatch(batchDocs);
                batchDocs.clear();
                runningBatchBytes = 0;
            }
        }
        if (RuntimeConfig.isExportRunning() && !batchDocs.isEmpty()) {
            flushBatch(batchDocs);
        }
        logPeriodicExportSummary(checked, exported);
    }

    private static void logPeriodicExportSummary(int checked, int exported) {
        if (checked <= 0) {
            return;
        }
        if (exported > 0) {
            Logger.logInfoPanelOnly("[PeriodicExport] Sitemap: " + exported
                    + " new item(s); " + checked + " in-scope checked.");
            return;
        }
        Logger.logDebug("[PeriodicExport] Sitemap: no new items; " + checked + " in-scope checked.");
    }

    private static SitemapWorkItem toWorkItem(
            HttpRequestResponse item,
            ConfigState.State state,
            SnapshotScopeCache scopeCache) {
        HttpRequest request = item.request();
        if (request == null) {
            return null;
        }
        String url = RequestResponseDocBuilder.safeRequestUrl(request, "Sitemap");
        if (url == null) {
            url = "";
        }
        boolean burpInScope = scopeCache.isInScope(url);
        if (!ScopeFilter.shouldExport(state, url, burpInScope)) {
            return null;
        }
        return new SitemapWorkItem(item, burpInScope);
    }

    /** Returns sitemap request/response items, tolerating transient Burp lifecycle nulls. */
    private static List<HttpRequestResponse> safeSiteMapItems(MontoyaApi api) {
        try {
            if (api == null) {
                return null;
            }
            var siteMap = api.siteMap();
            if (siteMap == null) {
                return null;
            }
            return siteMap.requestResponses();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void flushBatch(List<PreparedExportDocument> batchDocs) {
        String activeBaseUrl = RuntimeConfig.openSearchUrl();
        boolean openSearchActive = RuntimeConfig.isOpenSearchActive();
        var outcome = OpenSearchClientWrapper.pushPreparedBulk(activeBaseUrl, sitemapIndexName(), "sitemap", batchDocs);
        BulkOutcomeRecorder.record("sitemap", "Sitemap", "Bulk push", outcome, openSearchActive);
    }

    static Map<String, Object> buildSitemapDoc(HttpRequestResponse item) {
        return buildSitemapDoc(item, false);
    }

    private static Map<String, Object> buildSitemapDoc(
            HttpRequestResponse item,
            boolean burpInScope) {
        Map<String, Object> doc = new LinkedHashMap<>();
        HttpRequest request = item.request();
        HttpService service = item.httpService();
        HttpResponse response = item.hasResponse() ? item.response() : null;

        Map<String, Object> requestDoc = request == null ? null : RequestResponseDocBuilder.buildSitemapRequestDoc(request);
        String url = request == null
                ? ""
                : nullToEmpty(RequestResponseDocBuilder.buildBestEffortUrl(request, service, requestDoc, "Sitemap"));
        doc.put("burp", buildBurpDoc(item, burpInScope));

        if (requestDoc != null) {
            requestDoc.put("url", url);
            requestDoc.put("port", service == null ? null : service.port());
            requestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                    service == null ? null : (service.secure() ? "https" : "http"),
                    RequestResponseDocBuilder.safeRequestHttpVersion(request)));
        }
        doc.put("request", requestDoc);
        if (response != null) {
            Map<String, Object> responseDoc = RequestResponseDocBuilder.buildTrafficResponseDoc(response);
            TrafficPairMarkers.overlayPairMarkers(requestDoc, responseDoc, item);
            doc.put("response", responseDoc);
        } else {
            TrafficPairMarkers.overlayPairMarkers(requestDoc, null, item);
            doc.put("response", null);
        }

        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));

        return doc;
    }

    private static Map<String, Object> buildBurpDoc(HttpRequestResponse item, boolean burpInScope) {
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("is_in_scope", burpInScope);
        burp.put("timing", BurpTimingFields.from(item));
        putAnnotations(burp, item.annotations());
        return burp;
    }

    private static void putAnnotations(Map<String, Object> burp, Annotations annotations) {
        if (annotations == null) {
            return;
        }
        if (annotations.hasNotes()) {
            burp.put("notes", annotations.notes());
        }
        if (annotations.hasHighlightColor()) {
            HighlightColor color = annotations.highlightColor();
            burp.put("highlight", color == null ? null : color.name());
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
