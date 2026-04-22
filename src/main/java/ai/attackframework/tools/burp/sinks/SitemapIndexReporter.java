package ai.attackframework.tools.burp.sinks;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;

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
    private static final String SOURCE_VALUE = "burp-exporter";

    private static volatile ScheduledExecutorService scheduler;
    /** Keys (request_id) of items already pushed this session; only push new on 30s run. */
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
            if (scheduler != null) {
                scheduler.submit(() -> {
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
        if (scheduler != null) {
            return;
        }
        synchronized (SitemapIndexReporter.class) {
            if (scheduler != null) {
                return;
            }
            ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "attackframework-sitemap-reporter");
                t.setDaemon(true);
                return t;
            });
            exec.scheduleAtFixedRate(
                    SitemapIndexReporter::pushNewItemsOnly,
                    INTERVAL_SECONDS,
                    INTERVAL_SECONDS,
                    TimeUnit.SECONDS);
            scheduler = exec;
        }
    }

    /**
     * Stops the periodic scheduler and clears per-session reporter state.
     *
     * <p>Safe to call from any thread. The next {@link #start()} call creates a fresh scheduler.</p>
     */
    public static void stop() {
        ScheduledExecutorService exec;
        synchronized (SitemapIndexReporter.class) {
            exec = scheduler;
            scheduler = null;
        }
        ReporterExecutors.shutdownNowAndAwait(exec);
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
            boolean openSearchActive = pushAll && isOpenSearchActive();
            boolean fileActive = pushAll && RuntimeConfig.isAnyFileExportEnabled();
            long startNs = pushAll ? System.nanoTime() : 0L;

            for (HttpRequestResponse item : items) {
                if (!RuntimeConfig.isExportRunning()) {
                    break;
                }
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
                Map<String, Object> doc = buildSitemapDoc(item);
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

    private static boolean isOpenSearchActive() {
        String activeBaseUrl = RuntimeConfig.openSearchUrl();
        return activeBaseUrl != null && !activeBaseUrl.isBlank();
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
        boolean openSearchActive = !activeBaseUrl.isBlank();
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

    private static Map<String, Object> buildSitemapDoc(HttpRequestResponse item) {
        Map<String, Object> doc = new LinkedHashMap<>();
        HttpRequest request = item.request();
        HttpService service = item.httpService();
        HttpResponse response = item.hasResponse() ? item.response() : null;

        Map<String, Object> requestDoc = request == null ? null : RequestResponseDocBuilder.buildRequestDoc(request);
        String url = request == null
                ? ""
                : nullToEmpty(RequestResponseDocBuilder.buildBestEffortUrl(request, service, requestDoc, "Sitemap"));
        String method = valueAsString(requestDoc, "method");
        String httpVersion = valueAsString(requestDoc, "http_version");
        String path = valueAsString(requestDoc, "path");
        String query = valueAsString(requestDoc, "query");
        doc.put("url", url);
        doc.put("host", service != null ? service.host() : "");
        doc.put("port", service != null ? service.port() : 0);
        doc.put("protocol_transport", service != null ? (service.secure() ? "https" : "http") : "");
        doc.put("protocol_application", "http");
        doc.put("protocol_sub", httpVersion);
        doc.put("method", method);

        if (response != null) {
            doc.put("status_code", (int) response.statusCode());
            doc.put("status_reason", nullToEmpty(response.reasonPhrase()));
            var mime = response.mimeType();
            doc.put("content_type", mime != null ? mime.name() : null);
            byte[] bodyBytes = response.body() != null ? response.body().getBytes() : null;
            doc.put("content_length", bodyBytes != null ? bodyBytes.length : null);
            doc.put("title", getPageTitle(response));
        } else {
            doc.put("status_code", null);
            doc.put("status_reason", null);
            doc.put("content_type", null);
            doc.put("content_length", null);
            doc.put("title", null);
        }

        if (request != null && request.parameters() != null) {
            List<String> paramNames = request.parameters().stream()
                    .map(p -> p.name() != null ? p.name() : "")
                    .collect(Collectors.toList());
            doc.put("param_names", paramNames);
        } else {
            doc.put("param_names", List.of());
        }

        doc.put("path", path);
        doc.put("query_string", query);
        doc.put("request_id", requestId(url, method));
        doc.put("source", SOURCE_VALUE);

        doc.put("request", requestDoc);
        if (response != null) {
            doc.put("response", RequestResponseDocBuilder.buildResponseDoc(response));
        } else {
            doc.put("response", null);
        }

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        meta.put("indexed_at", Instant.now().toString());
        doc.put("document_meta", meta);

        return doc;
    }

    private static String getPageTitle(HttpResponse response) {
        if (response == null) {
            return null;
        }
        try {
            var attrs = response.attributes(AttributeType.PAGE_TITLE);
            if (attrs != null && !attrs.isEmpty()) {
                return String.valueOf(attrs.get(0).value());
            }
        } catch (Exception e) {
            Logger.logDebug("[Sitemap] response.attributes(PAGE_TITLE) failed: " + e.getMessage());
        }
        return null;
    }

    private static String valueAsString(Map<String, Object> requestDoc, String key) {
        if (requestDoc == null) {
            return "";
        }
        Object value = requestDoc.get(key);
        return value == null ? "" : value.toString();
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
