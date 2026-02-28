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

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
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
    private static final int BULK_BATCH_SIZE = 100;
    /** Flush when batch exceeds this approximate payload size (bytes) so large bodies don't produce huge bulk requests. */
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024; // 5 MB
    private static final String SITEMAP_INDEX = IndexNaming.INDEX_PREFIX + "-sitemap";
    private static final String SCHEMA_VERSION = "1";
    private static final String SOURCE_VALUE = "burp-exporter";

    private static volatile ScheduledExecutorService scheduler;
    /** Keys (request_id) of items already pushed this session; only push new on 30s run. */
    private static final Set<String> pushedItemKeys = ConcurrentHashMap.newKeySet();
    private static volatile boolean runInProgress;

    private SitemapIndexReporter() {}

    /**
     * Pushes all current sitemap items once (e.g. initial push on Start). Safe to call
     * from any thread. Schedules work on the reporter thread and returns immediately so
     * the UI does not freeze. No-op if export is not running, OpenSearch URL is blank,
     * or Sitemap is not in the selected data sources.
     */
    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
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
                scheduler.submit(() -> pushItems(api, baseUrl, true));
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logDebug("Sitemap index: push failed: " + msg);
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

    static void pushNewItemsOnly() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
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
            pushItems(api, baseUrl, false);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logDebug("Sitemap index: push failed: " + msg);
        }
    }

    private static void pushItems(MontoyaApi api, String baseUrl, boolean pushAll) {
        if (runInProgress) {
            return;
        }
        runInProgress = true;
        try {
            List<HttpRequestResponse> items = api.siteMap().requestResponses();
            if (items == null) {
                return;
            }
            var state = RuntimeConfig.getState();
            List<String> batchKeys = new ArrayList<>(BULK_BATCH_SIZE);
            List<Map<String, Object>> batchDocs = new ArrayList<>(BULK_BATCH_SIZE);
            long runningBatchBytes = 0;

            for (HttpRequestResponse item : items) {
                HttpRequest request = item.request();
                if (request == null) {
                    continue;
                }
                String url = request.url();
                if (url == null) {
                    url = "";
                }
                boolean burpInScope = api.scope().isInScope(url);
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

                if (batchDocs.size() >= BULK_BATCH_SIZE || runningBatchBytes >= BULK_MAX_BYTES) {
                    flushBatch(baseUrl, batchKeys, batchDocs);
                    batchKeys.clear();
                    batchDocs.clear();
                    runningBatchBytes = 0;
                }
            }
            if (!batchDocs.isEmpty()) {
                flushBatch(baseUrl, batchKeys, batchDocs);
            }
        } finally {
            runInProgress = false;
        }
    }

    private static void flushBatch(String baseUrl, List<String> batchKeys, List<Map<String, Object>> batchDocs) {
        int successCount = OpenSearchClientWrapper.pushBulk(baseUrl, SITEMAP_INDEX, batchDocs);
        int failureCount = batchDocs.size() - successCount;
        ExportStats.recordSuccess("sitemap", successCount);
        ExportStats.recordFailure("sitemap", failureCount);
        if (failureCount > 0) {
            ExportStats.recordLastError("sitemap", "Bulk had " + failureCount + " failure(s)");
        }
        if (successCount == batchDocs.size()) {
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

        String url = request != null ? request.url() : "";
        String method = request != null ? request.method() : "";
        doc.put("url", nullToEmpty(url));
        doc.put("host", service != null ? service.host() : "");
        doc.put("port", service != null ? service.port() : 0);
        doc.put("protocol_transport", service != null ? (service.secure() ? "https" : "http") : "");
        doc.put("protocol_application", null);
        doc.put("protocol_sub", null);
        doc.put("method", nullToEmpty(method));

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

        doc.put("node_type", null);
        doc.put("path", request != null ? nullToEmpty(request.path()) : "");
        doc.put("query_string", request != null ? nullToEmpty(request.query()) : "");
        doc.put("request_id", requestId(url, method));
        doc.put("source", SOURCE_VALUE);
        doc.put("tech_stack", null);
        doc.put("tags", null);

        if (request != null) {
            doc.put("request", RequestResponseDocBuilder.buildRequestDoc(request));
        } else {
            doc.put("request", null);
        }
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
        doc.put("summary", null);
        doc.put("cluster_id", null);

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

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
