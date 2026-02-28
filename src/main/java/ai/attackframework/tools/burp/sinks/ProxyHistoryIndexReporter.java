package ai.attackframework.tools.burp.sinks;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.Version;
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

    private static final int BULK_BATCH_SIZE = 100;
    private static final String TRAFFIC_INDEX = IndexNaming.INDEX_PREFIX + "-traffic";
    private static final String SCHEMA_VERSION = "1";

    private ProxyHistoryIndexReporter() {}

    /**
     * Pushes all current proxy history items once (on Start), in batches. Safe to call
     * from any thread; work runs on a background thread and returns immediately.
     * No-op if export is not running, OpenSearch URL is blank, or PROXY_HISTORY is not selected.
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
            List<String> trafficTypes = RuntimeConfig.getState().trafficToolTypes();
            if (trafficTypes == null || !trafficTypes.contains("PROXY_HISTORY")) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null || api.proxy() == null) {
                return;
            }
            ExecutorService exec = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "attackframework-proxy-history-once");
                t.setDaemon(true);
                return t;
            });
            exec.submit(() -> pushItems(api, baseUrl));
            exec.shutdown();
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logDebug("Proxy History index: push failed: " + msg);
        }
    }

    private static void pushItems(MontoyaApi api, String baseUrl) {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (history == null || history.isEmpty()) {
            return;
        }
        List<Map<String, Object>> batch = new ArrayList<>();
        for (ProxyHttpRequestResponse item : history) {
            Map<String, Object> doc = buildDocument(api, item);
            if (doc != null) {
                batch.add(doc);
            }
        }
        if (batch.isEmpty()) {
            return;
        }
        long startNs = System.nanoTime();
        int success = 0;
        for (int i = 0; i < batch.size(); i += BULK_BATCH_SIZE) {
            List<Map<String, Object>> chunk = batch.subList(i, Math.min(i + BULK_BATCH_SIZE, batch.size()));
            success += OpenSearchClientWrapper.pushBulk(baseUrl, TRAFFIC_INDEX, chunk);
        }
        long durationMs = (System.nanoTime() - startNs) / 1_000_000;
        ExportStats.recordLastPush("traffic", durationMs);
        ExportStats.recordSuccess("traffic", success);
        if (success < batch.size()) {
            ExportStats.recordFailure("traffic", batch.size() - success);
        }
        Logger.logTrace("[ProxyHistory] pushed " + success + " of " + batch.size());
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
        boolean inScope = ScopeFilter.shouldExport(RuntimeConfig.getState(), url, burpInScope);

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", request.url());
        document.put("host", service == null ? null : service.host());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", scheme);
        document.put("http_version", request.httpVersion());
        document.put("tool", "Proxy History");
        document.put("tool_type", "PROXY_HISTORY");
        document.put("in_scope", inScope);
        document.put("message_id", item.id());
        document.put("proxy_history_id", item.id());
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

        return document;
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
        m.put("body", null);
        m.put("body_length", 0);
        m.put("body_content", null);
        m.put("body_offset", 0);
        m.put("markers", List.of());
        return m;
    }
}
