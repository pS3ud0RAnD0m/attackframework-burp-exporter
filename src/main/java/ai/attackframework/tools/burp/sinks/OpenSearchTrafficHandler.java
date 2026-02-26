package ai.attackframework.tools.burp.sinks;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.TrafficExportStats;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

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
    private static final int BODY_PREVIEW_MAX_CHARS = 4096;

    /** Delay after which a request with no response is exported as an orphan (Chromium-aligned). */
    private static final long ORPHAN_TIMEOUT_MS = 120_000L;
    private static final int ORPHAN_CHECK_INTERVAL_SECONDS = 30;
    /** Sentinel for response when no response was received (e.g. timeout). */
    private static final int ORPHAN_STATUS = 0;
    private static final String ORPHAN_REASON_PHRASE = "Timeout";

    private static final ConcurrentHashMap<Integer, PendingOrphan> pendingOrphans = new ConcurrentHashMap<>();

    static {
        ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "attackframework-orphan-export");
            t.setDaemon(true);
            return t;
        });
        exec.scheduleAtFixedRate(
                OpenSearchTrafficHandler::flushOrphanedRequests,
                ORPHAN_CHECK_INTERVAL_SECONDS,
                ORPHAN_CHECK_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * Whether traffic from this tool source should be exported to the traffic index.
     * Only Proxy and Repeater are allowed; all other tools (Scanner, Extensions, etc.) are omitted.
     */
    private static boolean shouldExportTrafficByToolSource(ToolType toolType) {
        return toolType == ToolType.PROXY || toolType == ToolType.REPEATER;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (!RuntimeConfig.isExportRunning()
                || !RuntimeConfig.isOpenSearchTrafficEnabled()
                || RuntimeConfig.openSearchUrl().isBlank()) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (!ScopeFilter.shouldExport(
                RuntimeConfig.getState(), request.url(), request.isInScope())) {
            return RequestToBeSentAction.continueWith(request);
        }
        ToolSource toolSource = request.toolSource();
        ToolType toolType = toolSource == null ? null : toolSource.toolType();
        if (!shouldExportTrafficByToolSource(toolType)) {
            return RequestToBeSentAction.continueWith(request);
        }
        Map<String, Object> skeleton = buildOrphanDocumentSkeleton(request);
        if (skeleton != null) {
            pendingOrphans.put(request.messageId(), new PendingOrphan(skeleton, System.currentTimeMillis()));
        }
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!RuntimeConfig.isExportRunning()) {
            return ResponseReceivedAction.continueWith(response);
        }
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

        boolean inScope = ScopeFilter.shouldExport(
                RuntimeConfig.getState(), request.url(), request.isInScope());
        if (!inScope) {
            return ResponseReceivedAction.continueWith(response);
        }

        ToolSource respToolSource = response.toolSource();
        ToolType respToolType = respToolSource == null ? null : respToolSource.toolType();
        if (!shouldExportTrafficByToolSource(respToolType)) {
            pendingOrphans.remove(response.messageId());
            return ResponseReceivedAction.continueWith(response);
        }

        Map<String, Object> document = buildDocument(response, request, inScope);
        long startNs = System.nanoTime();
        boolean success = OpenSearchClientWrapper.pushDocument(baseUrl, INDEX_NAME, document);
        long durationMs = (System.nanoTime() - startNs) / 1_000_000;
        TrafficExportStats.setLastPushDurationMs(durationMs);

        if (success) {
            TrafficExportStats.incrementSuccess();
        } else {
            TrafficExportStats.incrementFailure();
            String errMsg = "Failed to index traffic document to " + INDEX_NAME;
            TrafficExportStats.setLastError(errMsg);
            Logger.logError("[OpenSearch] " + errMsg);
        }

        pendingOrphans.remove(response.messageId());
        return ResponseReceivedAction.continueWith(response);
    }

    /**
     * Builds the traffic document for OpenSearch. Caller must hold Burp HTTP thread.
     *
     * @param response the received response (with initiating request)
     * @param request  the initiating request
     * @param inScope  whether the request passed scope filter
     * @return map matching traffic index mapping (never null)
     */
    Map<String, Object> buildDocument(HttpResponseReceived response, HttpRequest request, boolean inScope) {
        HttpService service = request.httpService();
        String scheme = service == null ? null : (service.secure() ? "https" : "http");
        ToolSource toolSource = response.toolSource();
        ToolType toolType = toolSource == null ? null : toolSource.toolType();

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", request.url());
        document.put("host", service == null ? null : service.host());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", scheme);
        document.put("http_version", request.httpVersion());
        document.put("tool", toolType == null ? null : toolType.toolName());
        document.put("tool_type", toolType == null ? null : toolType.name());
        document.put("in_scope", inScope);
        document.put("message_id", response.messageId());
        putAnnotations(document, response.annotations());
        document.put("path", request.path());
        document.put("method", request.method());
        document.put("status", (int) response.statusCode());
        MimeType responseMime = response.mimeType();
        document.put("mime_type", responseMime == null ? null : responseMime.name());

        document.put("request", buildRequestDoc(request));
        document.put("response", buildResponseDoc(response));

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        document.put("document_meta", meta);

        return document;
    }

    private static void putAnnotations(Map<String, Object> document, Annotations annotations) {
        if (annotations == null) {
            return;
        }
        if (annotations.hasNotes()) {
            document.put("comment", annotations.notes());
        }
        if (annotations.hasHighlightColor()) {
            HighlightColor color = annotations.highlightColor();
            document.put("highlight", color == null ? null : color.name());
        }
    }

    /**
     * Builds the document skeleton for an orphaned request (no response received).
     * Caller must hold Burp HTTP thread. Does not include {@code response}; add via
     * {@link #buildOrphanResponse()} when exporting.
     */
    private Map<String, Object> buildOrphanDocumentSkeleton(HttpRequestToBeSent request) {
        HttpService service = request.httpService();
        String scheme = service == null ? null : (service.secure() ? "https" : "http");
        ToolSource toolSource = request.toolSource();
        ToolType toolType = toolSource == null ? null : toolSource.toolType();
        boolean inScope = ScopeFilter.shouldExport(
                RuntimeConfig.getState(), request.url(), request.isInScope());

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", request.url());
        document.put("host", service == null ? null : service.host());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", scheme);
        document.put("http_version", request.httpVersion());
        document.put("tool", toolType == null ? null : toolType.toolName());
        document.put("tool_type", toolType == null ? null : toolType.name());
        document.put("in_scope", inScope);
        document.put("message_id", request.messageId());
        putAnnotations(document, request.annotations());
        document.put("path", request.path());
        document.put("method", request.method());
        document.put("status", ORPHAN_STATUS);
        document.put("mime_type", (String) null);

        document.put("request", buildRequestDoc(request));

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        document.put("document_meta", meta);

        return document;
    }

    private static Map<String, Object> buildOrphanResponse() {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", ORPHAN_STATUS);
        resp.put("reason_phrase", ORPHAN_REASON_PHRASE);
        return resp;
    }

    /**
     * Runs on a daemon thread. Exports pending requests that have not received a response
     * within {@link #ORPHAN_TIMEOUT_MS} as request-only documents with
     * {@code response.status = 0} and {@code response.reason_phrase = "Timeout"}.
     */
    private static void flushOrphanedRequests() {
        if (!RuntimeConfig.isExportRunning()
                || !RuntimeConfig.isOpenSearchTrafficEnabled()) {
            return;
        }
        String baseUrl = RuntimeConfig.openSearchUrl();
        if (baseUrl == null || baseUrl.isBlank()) {
            return;
        }
        long now = System.currentTimeMillis();
        List<Integer> toFlush = new ArrayList<>();
        for (Map.Entry<Integer, PendingOrphan> e : pendingOrphans.entrySet()) {
            if (now - e.getValue().timestamp >= ORPHAN_TIMEOUT_MS) {
                toFlush.add(e.getKey());
            }
        }
        for (Integer messageId : toFlush) {
            PendingOrphan po = pendingOrphans.remove(messageId);
            if (po == null) {
                continue;
            }
            Map<String, Object> doc = new LinkedHashMap<>(po.documentSkeleton);
            doc.put("response", buildOrphanResponse());
            long startNs = System.nanoTime();
            boolean success = OpenSearchClientWrapper.pushDocument(baseUrl, INDEX_NAME, doc);
            long durationMs = (System.nanoTime() - startNs) / 1_000_000;
            TrafficExportStats.setLastPushDurationMs(durationMs);
            if (success) {
                TrafficExportStats.incrementSuccess();
            } else {
                TrafficExportStats.incrementFailure();
                String errMsg = "Failed to index orphan traffic document to " + INDEX_NAME;
                TrafficExportStats.setLastError(errMsg);
                Logger.logError("[OpenSearch] " + errMsg);
            }
        }
    }

    private static final class PendingOrphan {
        final Map<String, Object> documentSkeleton;
        final long timestamp;

        PendingOrphan(Map<String, Object> documentSkeleton, long timestamp) {
            this.documentSkeleton = documentSkeleton;
            this.timestamp = timestamp;
        }
    }

    private Map<String, Object> buildRequestDoc(HttpRequest request) {
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("method", request.method());
        req.put("path", request.path());
        req.put("path_without_query", nullToEmpty(request.pathWithoutQuery()));
        req.put("query", nullToEmpty(request.query()));
        req.put("file_extension", nullToEmpty(request.fileExtension()));
        req.put("http_version", request.httpVersion());

        burp.api.montoya.http.message.ContentType contentType = request.contentType();
        req.put("content_type", contentType == null ? null : contentType.toString());
        req.put("content_type_enum", contentType == null ? null : contentType.name());

        req.put("headers", headersToList(request.headers()));
        req.put("parameters", parametersToList(request.parameters()));

        byte[] bodyBytes = request.body() == null ? null : request.body().getBytes();
        int bodyLen = bodyBytes == null ? 0 : bodyBytes.length;
        req.put("body_length", bodyLen);
        req.put("body_offset", request.bodyOffset());
        req.put("body_preview", bodyPreview(bodyBytes));
        req.put("body_content", bodyContentString(bodyBytes));

        req.put("markers", markersToList(request.markers()));
        return req;
    }

    private Map<String, Object> buildResponseDoc(HttpResponseReceived response) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", (int) response.statusCode());
        resp.put("status_code_class", statusCodeClassName(response.statusCode()));
        resp.put("reason_phrase", response.reasonPhrase());
        resp.put("http_version", response.httpVersion());
        resp.put("headers", headersToList(response.headers()));
        resp.put("cookies", cookiesToList(response.cookies()));

        MimeType mime = response.mimeType();
        MimeType stated = response.statedMimeType();
        MimeType inferred = response.inferredMimeType();
        resp.put("mime_type", mime == null ? null : mime.name());
        resp.put("stated_mime_type", stated == null ? null : stated.name());
        resp.put("inferred_mime_type", inferred == null ? null : inferred.name());

        byte[] bodyBytes = response.body() == null ? null : response.body().getBytes();
        int bodyLen = bodyBytes == null ? 0 : bodyBytes.length;
        resp.put("body_length", bodyLen);
        resp.put("body_offset", response.bodyOffset());
        resp.put("body_preview", bodyPreview(bodyBytes));
        resp.put("body_content", bodyBytes == null ? null : response.bodyToString());

        resp.put("markers", markersToList(response.markers()));

        putResponseAttributes(resp, response);
        return resp;
    }

    private static String statusCodeClassName(short statusCode) {
        for (StatusCodeClass c : StatusCodeClass.values()) {
            if (c.contains(statusCode)) {
                return c.name();
            }
        }
        return null;
    }

    private static List<Map<String, Object>> parametersToList(List<ParsedHttpParameter> parameters) {
        if (parameters == null || parameters.isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> out = new ArrayList<>(parameters.size());
        for (ParsedHttpParameter p : parameters) {
            Map<String, Object> entry = new LinkedHashMap<>(3);
            entry.put("name", p.name());
            entry.put("value", p.value());
            HttpParameterType type = p.type();
            entry.put("type", type == null ? null : type.name());
            out.add(entry);
        }
        return out;
    }

    private static List<Map<String, Object>> cookiesToList(List<Cookie> cookies) {
        if (cookies == null || cookies.isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> out = new ArrayList<>(cookies.size());
        for (Cookie c : cookies) {
            Map<String, Object> entry = new LinkedHashMap<>(5);
            entry.put("name", c.name());
            entry.put("value", c.value());
            entry.put("domain", c.domain());
            entry.put("path", c.path());
            Optional<java.time.ZonedDateTime> exp = c.expiration();
            entry.put("expiration", exp == null || exp.isEmpty() ? null : exp.get().toString());
            out.add(entry);
        }
        return out;
    }

    private static List<Map<String, Object>> markersToList(List<Marker> markers) {
        if (markers == null || markers.isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> out = new ArrayList<>(markers.size());
        for (Marker m : markers) {
            if (m == null || m.range() == null) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>(2);
            entry.put("start_index_inclusive", m.range().startIndexInclusive());
            entry.put("end_index_exclusive", m.range().endIndexExclusive());
            out.add(entry);
        }
        return out;
    }

    private static void putResponseAttributes(Map<String, Object> responseDoc, HttpResponseReceived response) {
        AttributeType[] types = new AttributeType[] {
            AttributeType.PAGE_TITLE,
            AttributeType.LOCATION,
            AttributeType.CONTENT_LENGTH,
            AttributeType.VISIBLE_TEXT,
            AttributeType.WORD_COUNT,
            AttributeType.VISIBLE_WORD_COUNT,
            AttributeType.LINE_COUNT,
            AttributeType.COOKIE_NAMES,
            AttributeType.CANONICAL_LINK,
            AttributeType.LIMITED_BODY_CONTENT,
            AttributeType.COMMENTS,
            AttributeType.NON_HIDDEN_FORM_INPUT_TYPES,
            AttributeType.ANCHOR_LABELS,
            AttributeType.TAG_NAMES,
            AttributeType.DIV_IDS,
            AttributeType.CSS_CLASSES,
            AttributeType.INPUT_SUBMIT_LABELS,
            AttributeType.BUTTON_SUBMIT_LABELS,
            AttributeType.INPUT_IMAGE_LABELS,
            AttributeType.ETAG_HEADER,
            AttributeType.LAST_MODIFIED_HEADER,
            AttributeType.CONTENT_LOCATION,
            AttributeType.OUTBOUND_EDGE_COUNT,
            AttributeType.OUTBOUND_EDGE_TAG_NAMES,
            AttributeType.BODY_CONTENT
        };
        try {
            List<Attribute> attrs = response.attributes(types);
            if (attrs == null) {
                return;
            }
            for (Attribute attr : attrs) {
                if (attr == null) {
                    continue;
                }
                String fieldName = attributeTypeToFieldName(attr.type());
                if (fieldName == null) {
                    continue;
                }
                Object value = attributeValue(attr);
                if (value != null) {
                    responseDoc.put(fieldName, value);
                }
            }
        } catch (Exception e) {
            Logger.logDebug("[Traffic] response.attributes() failed: " + e.getMessage());
        }
    }

    private static String attributeTypeToFieldName(AttributeType type) {
        if (type == null) {
            return null;
        }
        return type.name().toLowerCase();
    }

    private static Object attributeValue(Attribute attr) {
        if (attr == null) {
            return null;
        }
        try {
            return Integer.valueOf(attr.value());
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String bodyPreview(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        String s = bodyContentString(body);
        if (s == null || s.length() <= BODY_PREVIEW_MAX_CHARS) {
            return s;
        }
        return s.substring(0, BODY_PREVIEW_MAX_CHARS);
    }

    private static String bodyContentString(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            return new String(body, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
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