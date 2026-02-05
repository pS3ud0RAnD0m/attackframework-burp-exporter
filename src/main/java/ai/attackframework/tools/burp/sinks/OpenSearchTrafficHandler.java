package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Burp HTTP handler that indexes request/response traffic into the OpenSearch traffic index.
 *
 * <p>Runs on Burp's HTTP thread. Only indexes when OpenSearch traffic export is enabled, the
 * OpenSearch URL is set, and the request passes scope filtering. Document shape matches
 * {@code /opensearch/mappings/traffic.json}.</p>
 */
public final class OpenSearchTrafficHandler implements HttpHandler {

    private static final String INDEX_NAME = IndexNaming.INDEX_PREFIX + "-traffic";
    private static final String SCHEMA_VERSION = "1";

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!RuntimeConfig.isExportRunning()) {
            Logger.logTrace("[Traffic] skip: export not running");
            return ResponseReceivedAction.continueWith(response);
        }
        if (!RuntimeConfig.isOpenSearchTrafficEnabled()) {
            Logger.logTrace("[Traffic] skip: OpenSearch traffic not enabled");
            return ResponseReceivedAction.continueWith(response);
        }

        String baseUrl = RuntimeConfig.openSearchUrl();
        if (baseUrl.isBlank()) {
            Logger.logTrace("[Traffic] skip: OpenSearch URL blank");
            return ResponseReceivedAction.continueWith(response);
        }

        HttpRequest request = response.initiatingRequest();
        if (request == null) {
            Logger.logTrace("[Traffic] skip: no initiating request");
            return ResponseReceivedAction.continueWith(response);
        }

        boolean inScope = ScopeFilter.shouldExport(
                RuntimeConfig.getState(), request.url(), request.isInScope());
        if (!inScope) {
            Logger.logTrace("[Traffic] skip: out of scope url=" + truncateForLog(request.url(), 80));
            return ResponseReceivedAction.continueWith(response);
        }

        Map<String, Object> document = buildDocument(response, request, inScope);
        boolean success = OpenSearchClientWrapper.pushDocument(baseUrl, INDEX_NAME, document);
        if (success) {
            Logger.logDebug("[Traffic] indexed url=" + truncateForLog(request.url(), 80));
        } else {
            Logger.logError("[OpenSearch] Failed to index traffic document to " + INDEX_NAME);
        }

        return ResponseReceivedAction.continueWith(response);
    }

    private static String truncateForLog(String s, int maxLen) {
        if (s == null) return "null";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "...";
    }

    private Map<String, Object> buildDocument(HttpResponseReceived response, HttpRequest request, boolean inScope) {
        HttpService service = request.httpService();

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", request.url());
        document.put("host", service == null ? null : service.host());
        document.put("http_version", request.httpVersion());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", service == null ? null : (service.secure() ? "https" : "http"));
        document.put("tool", toolName(response.toolSource()));
        document.put("in_scope", inScope);

        Map<String, Object> requestDoc = new LinkedHashMap<>();
        requestDoc.put("method", request.method());
        requestDoc.put("path", request.path());
        requestDoc.put("headers", headersToList(request.headers()));
        document.put("request", requestDoc);

        Map<String, Object> responseDoc = new LinkedHashMap<>();
        responseDoc.put("status", (int) response.statusCode());
        responseDoc.put("headers", headersToList(response.headers()));
        document.put("response", responseDoc);

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        document.put("document_meta", meta);

        return document;
    }

    private String toolName(ToolSource toolSource) {
        if (toolSource == null) {
            return null;
        }
        ToolType type = toolSource.toolType();
        return type == null ? null : type.toolName();
    }

    /**
     * Converts Burp headers to a list of name/value maps for the traffic index mapping.
     *
     * @param headers Burp header list; {@code null} or empty yields an empty list
     * @return list of maps with {@code name} and {@code value} keys
     */
    private static List<Map<String, String>> headersToList(List<HttpHeader> headers) {
        if (headers == null || headers.isEmpty()) {
            return List.of();
        }
        List<Map<String, String>> out = new ArrayList<>(headers.size());
        for (HttpHeader h : headers) {
            Map<String, String> entry = new LinkedHashMap<>(2);
            entry.put("name", h.name());
            entry.put("value", h.value());
            out.add(entry);
        }
        return out;
    }
}