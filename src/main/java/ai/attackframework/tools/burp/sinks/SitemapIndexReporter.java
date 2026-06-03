package ai.attackframework.tools.burp.sinks;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.concurrent.LazyScheduler;
import ai.attackframework.tools.burp.utils.concurrent.SnapshotPacing;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
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
 * pushes only items not yet sent. Does not start a new run while the previous
 * is still in progress. Respects extension scope (All / Burp / Custom).
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
    /** Internal URL+method keys of items already pushed this session; only push new on 30s run. */
    private static final Set<String> pushedItemKeys = ConcurrentHashMap.newKeySet();
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
            Logger.logWarnPanelOnly("[Sitemap] Snapshot push failed: " + msg);
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
        pushedItemKeys.clear();
        runInProgress = false;
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
            Logger.logWarnPanelOnly("[Sitemap] Periodic push failed: " + msg);
        }
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
            var state = RuntimeConfig.getState();
            int batchSize = BatchSizeController.getInstance().getCurrentBatchSize();
            List<String> batchKeys = new ArrayList<>(batchSize);
            List<Map<String, Object>> batchDocs = new ArrayList<>(batchSize);
            long runningBatchBytes = 0;
            int attempted = 0;

            SnapshotSummary.Baseline baseline = pushAll ? SnapshotSummary.forIndexKey("sitemap") : null;
            boolean openSearchActive = pushAll && RuntimeConfig.isOpenSearchActive();
            boolean fileActive = pushAll && RuntimeConfig.isAnyFileExportEnabled();
            long startNs = pushAll ? System.nanoTime() : 0L;
            if (pushAll) {
                Logger.logInfoPanelOnly("[Sitemap] Exporting sitemap backlog: " + items.size() + " item(s).");
            }

            int processed = 0;
            for (HttpRequestResponse item : items) {
                if (!RuntimeConfig.isExportRunning()) {
                    break;
                }
                // Cooperative pacing: brief yield + GC duty-cycle gate every Nth iteration so a
                // very large sitemap (tens of thousands of items) does not starve the EDT or
                // saturate G1's concurrent threads.
                SnapshotPacing.paceItem(processed);
                processed++;
                HttpRequest request = item.request();
                if (request == null) {
                    continue;
                }
                String url = RequestResponseDocBuilder.safeRequestUrl(request, "Sitemap");
                if (url == null) {
                    url = "";
                }
                boolean burpInScope = safeBurpInScope(api, url);
                if (!ScopeFilter.shouldExport(state, url, burpInScope)) {
                    continue;
                }
                String method = request.method() != null ? request.method() : "";
                String key = requestId(url, method);
                if (!pushAll && pushedItemKeys.contains(key)) {
                    continue;
                }
                Map<String, Object> doc = buildSitemapDoc(item, burpInScope);
                if (doc == null) {
                    continue;
                }
                batchKeys.add(key);
                batchDocs.add(doc);
                runningBatchBytes += BulkPayloadEstimator.estimateBytes(doc);
                attempted++;

                if (batchDocs.size() >= BatchSizeController.getInstance().getCurrentBatchSize() || runningBatchBytes >= BULK_MAX_BYTES) {
                    flushBatch(batchKeys, batchDocs);
                    batchKeys.clear();
                    batchDocs.clear();
                    runningBatchBytes = 0;
                }
            }
            if (RuntimeConfig.isExportRunning() && !batchDocs.isEmpty()) {
                flushBatch(batchKeys, batchDocs);
            }

            if (baseline != null) {
                long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
                SnapshotSummary.logInfo("Sitemap", baseline, attempted, durationMs, openSearchActive, fileActive);
            }
        } finally {
            runInProgress = false;
        }
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

    private static boolean safeBurpInScope(MontoyaApi api, String url) {
        if (url == null) {
            return false;
        }
        try {
            if (api == null) {
                return false;
            }
            var scope = api.scope();
            return scope != null && scope.isInScope(url);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void flushBatch(List<String> batchKeys, List<Map<String, Object>> batchDocs) {
        String activeBaseUrl = RuntimeConfig.openSearchUrl();
        boolean openSearchActive = RuntimeConfig.isOpenSearchActive();
        int attempted = batchDocs.size();
        int successCount = OpenSearchClientWrapper.pushBulk(activeBaseUrl, sitemapIndexName(), "sitemap", batchDocs);
        BulkOutcomeRecorder.record("sitemap", "Sitemap", "Bulk push", attempted, successCount, openSearchActive);
        if (successCount == attempted) {
            pushedItemKeys.addAll(batchKeys);
        }
    }

    private static String requestId(String url, String method) {
        String raw = (url != null ? url : "") + "|" + (method != null ? method : "");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            return String.valueOf(raw.hashCode());
        }
    }

    static Map<String, Object> buildSitemapDoc(HttpRequestResponse item) {
        return buildSitemapDoc(item, false);
    }

    private static Map<String, Object> buildSitemapDoc(HttpRequestResponse item, boolean burpInScope) {
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
