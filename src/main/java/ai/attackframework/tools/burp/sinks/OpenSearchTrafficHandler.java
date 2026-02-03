package ai.attackframework.tools.burp.sinks;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

public class OpenSearchTrafficHandler implements HttpHandler {
    private static final String INDEX_NAME = IndexNaming.INDEX_PREFIX + "-traffic";
    private static final String SCHEMA_VERSION = "1";

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!RuntimeConfig.isOpenSearchTrafficEnabled()) {
            return ResponseReceivedAction.continueWith(response);
        }

        String baseUrl = RuntimeConfig.openSearchUrl();
        if (baseUrl.isBlank()) {
            return ResponseReceivedAction.continueWith(response);
        }

        HttpRequest request = response.initiatingRequest();
        if (request == null) {
            return ResponseReceivedAction.continueWith(response);
        }

        Map<String, Object> document = buildDocument(response, request);
        boolean success = OpenSearchClientWrapper.pushDocument(baseUrl, INDEX_NAME, document);
        if (!success) {
            Logger.logError("[OpenSearch] Failed to index traffic document to " + INDEX_NAME);
        }

        return ResponseReceivedAction.continueWith(response);
    }

    private Map<String, Object> buildDocument(HttpResponseReceived response, HttpRequest request) {
        HttpService service = request.httpService();

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", request.url());
        document.put("host", service == null ? null : service.host());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", service == null ? null : (service.secure() ? "https" : "http"));
        document.put("tool", toolName(response.toolSource()));
        document.put("in_scope", request.isInScope());

        Map<String, Object> requestDoc = new LinkedHashMap<>();
        requestDoc.put("http_version", request.httpVersion());
        requestDoc.put("method", request.method());
        requestDoc.put("path", request.path());
        requestDoc.put("headers", joinHeaders(request.headers()));
        requestDoc.put("body", encodeBody(request.body()));
        document.put("request", requestDoc);

        Map<String, Object> responseDoc = new LinkedHashMap<>();
        responseDoc.put("http_version", response.httpVersion());
        responseDoc.put("status", (int) response.statusCode());
        responseDoc.put("headers", joinHeaders(response.headers()));
        responseDoc.put("body", encodeBody(response.body()));
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

    private String joinHeaders(List<HttpHeader> headers) {
        if (headers == null || headers.isEmpty()) {
            return "";
        }
        return headers.stream()
                .map(HttpHeader::toString)
                .collect(Collectors.joining("\n"));
    }

    private String encodeBody(ByteArray body) {
        if (body == null || body.length() == 0) {
            return null;
        }
        return Base64.getEncoder().encodeToString(body.getBytes());
    }
}