package ai.attackframework.tools.burp.sinks;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;

import ai.attackframework.tools.burp.utils.Logger;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

/**
 * Builds request and response sub-documents in the same shape as the traffic index,
 * for use by {@link TrafficHttpHandler}, {@link SitemapIndexReporter}, and findings evidence pairs.
 */
public final class RequestResponseDocBuilder {

    private RequestResponseDocBuilder() {}

    /** @see RequestResponseParametersSupport.ParametersResult */
    public record ParametersResult(
            List<Map<String, Object>> entries,
            int droppedSynthesized,
            boolean bodyEnumerationSkipped) {
        private static ParametersResult from(RequestResponseParametersSupport.ParametersResult result) {
            return new ParametersResult(result.entries(), result.droppedSynthesized(), result.bodyEnumerationSkipped());
        }
    }

    static ParametersResult collectParameters(HttpRequest request, boolean includeBody) {
        return ParametersResult.from(RequestResponseParametersSupport.collectParameters(request, includeBody));
    }

    static ParametersResult parametersToList(List<ParsedHttpParameter> parameters, boolean includeBody) {
        return ParametersResult.from(RequestResponseParametersSupport.parametersToList(parameters, includeBody));
    }

    static void recordParameterTelemetry(
            HttpRequest request,
            ContentType contentType,
            int retained,
            int droppedSynthesized,
            boolean bodyEnumerationSkipped) {
        RequestResponseParametersSupport.recordParameterTelemetry(
                request, contentType, retained, droppedSynthesized, bodyEnumerationSkipped);
    }

    static boolean shouldIncludeBodyParameters(
            ContentType contentType, List<HttpHeader> headers, String inferredContentType) {
        return RequestResponseParametersSupport.shouldIncludeBodyParameters(
                contentType, headers, inferredContentType);
    }

    static String inferRequestContentType(byte[] bodyBytes, List<HttpHeader> headers) {
        return RequestResponseParametersSupport.inferRequestContentType(bodyBytes, headers);
    }

    public static List<Map<String, Object>> convertMarkersToList(List<Marker> markers) {
        return HttpMessageDocSupport.convertMarkersToList(markers);
    }

    public static List<Map<String, Object>> convertTrafficMarkersToList(List<Marker> markers) {
        return HttpMessageDocSupport.convertTrafficMarkersToList(markers);
    }

    static String statusCodeClassName(short statusCode) {
        return RequestResponseParametersSupport.statusCodeClassName(statusCode);
    }

    /**
     * Builds a request sub-document for findings/sitemap indices (legacy flat field names).
     */
    public static Map<String, Object> buildRequestDoc(HttpRequest request) {
        if (request == null) {
            return buildFallbackRequestDoc(null, false);
        }
        try {
            return buildRequestDocStrict(request);
        } catch (RuntimeException e) {
            Logger.logDebug("[RequestResponseDocBuilder] request fallback due to malformed request: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return buildFallbackRequestDoc(request, false);
        }
    }

    /**
     * Builds a request sub-document for the traffic index (nested {@code content_type}, headers,
     * parameters, body).
     */
    public static Map<String, Object> buildTrafficRequestDoc(HttpRequest request) {
        if (request == null) {
            return buildFallbackRequestDoc(null, true);
        }
        try {
            return buildTrafficRequestDocStrict(request);
        } catch (RuntimeException e) {
            Logger.logDebug("[RequestResponseDocBuilder] traffic request fallback due to malformed request: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return buildFallbackRequestDoc(request, true);
        }
    }

    /**
     * Builds a request sub-document for the sitemap index using the traffic shape but URL-only
     * parameters. Burp's sitemap is a URL inventory, and avoiding unfiltered parameter enumeration
     * keeps large or content-type-spoofed bodies from materializing synthetic BODY parameters.
     */
    public static Map<String, Object> buildSitemapRequestDoc(HttpRequest request) {
        if (request == null) {
            return buildFallbackSitemapRequestDoc(null);
        }
        try {
            return buildSitemapRequestDocStrict(request);
        } catch (RuntimeException e) {
            Logger.logDebug("[RequestResponseDocBuilder] sitemap request fallback due to malformed request: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return buildFallbackSitemapRequestDoc(request);
        }
    }

    /**
     * Resolves the best-effort request URL for top-level traffic documents.
     *
     * <p>When {@link HttpRequest#url()} throws for malformed or partially bound Repeater requests,
     * this helper reconstructs a usable URL from {@link HttpService} plus the already-recovered
     * request path so top-level fields stay aligned with the nested request document.</p>
     *
     * @param request request whose direct URL accessor may throw
     * @param service HTTP service backing the request
     * @param requestDoc already-built request sub-document, usually from {@link #buildTrafficRequestDoc(HttpRequest)}
     *     or {@link #buildRequestDoc(HttpRequest)}
     * @param logPrefix logger prefix without brackets, for example {@code "RepeaterTabs"}
     * @return direct URL when available, otherwise a best-effort reconstructed URL or {@code null}
     */
    public static String buildBestEffortUrl(
            HttpRequest request,
            HttpService service,
            Map<String, Object> requestDoc,
            String logPrefix) {
        String directUrl = safeRequestUrl(request, logPrefix);
        if (directUrl != null) {
            return directUrl;
        }
        String path = HttpMessageDocSupport.normalizeBlank(requestPathWithQuery(requestDoc));
        if (path == null) {
            return null;
        }
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return path;
        }
        if (service == null || HttpMessageDocSupport.normalizeBlank(service.host()) == null) {
            return null;
        }
        String scheme = service.secure() ? "https" : "http";
        String normalizedPath = path.startsWith("/") ? path : "/" + path;
        return scheme + "://" + service.host() + portSuffix(scheme, service.port()) + normalizedPath;
    }

    private static Map<String, Object> buildRequestDocStrict(HttpRequest request) {
        Map<String, Object> req = new LinkedHashMap<>();
        putRequestCoreFields(req, request.method(), request.path(), request.pathWithoutQuery(),
                request.query(), request.fileExtension(), false);

        burp.api.montoya.http.message.ContentType contentType = request.contentType();
        List<HttpHeader> requestHeaders = request.headers();
        byte[] bodyBytes = request.body() == null ? null : request.body().getBytes();
        String inferredContentType = RequestResponseParametersSupport.inferRequestContentType(bodyBytes, requestHeaders);
        putLegacyRequestContentTypeFields(req, contentType, inferredContentType);

        req.put("headers", HttpMessageDocSupport.buildHeadersObject(requestHeaders));
        boolean includeBody = RequestResponseParametersSupport.shouldIncludeBodyParameters(contentType, requestHeaders, inferredContentType);
        ParametersResult parametersResult = ParametersResult.from(
                RequestResponseParametersSupport.collectParameters(request, includeBody));
        req.put("parameters", parametersResult.entries());
        RequestResponseParametersSupport.recordParameterTelemetry(request, contentType, parametersResult.entries().size(),
                parametersResult.droppedSynthesized(), parametersResult.bodyEnumerationSkipped());

        HttpMessageDocSupport.putBodyFields(
                req,
                bodyBytes,
                requestHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                false,
                request.bodyOffset());

        req.put("markers", HttpMessageDocSupport.markersToList(request.markers()));
        return req;
    }

    private static Map<String, Object> buildTrafficRequestDocStrict(HttpRequest request) {
        Map<String, Object> req = new LinkedHashMap<>();
        putRequestCoreFields(req, request.method(), request.path(), request.pathWithoutQuery(),
                request.query(), request.fileExtension(), true);

        burp.api.montoya.http.message.ContentType contentType = request.contentType();
        List<HttpHeader> requestHeaders = request.headers();
        byte[] bodyBytes = request.body() == null ? null : request.body().getBytes();
        String inferredContentType = RequestResponseParametersSupport.inferRequestContentType(bodyBytes, requestHeaders);
        req.put("header", HttpMessageDocSupport.buildRequestHeaderValueObject(requestHeaders, inferredContentType));
        boolean includeBody = RequestResponseParametersSupport.shouldIncludeBodyParameters(contentType, requestHeaders, inferredContentType);
        ParametersResult parametersResult = ParametersResult.from(
                RequestResponseParametersSupport.collectParameters(request, includeBody));
        req.put("parameters", parametersResult.entries());
        RequestResponseParametersSupport.recordParameterTelemetry(request, contentType, parametersResult.entries().size(),
                parametersResult.droppedSynthesized(), parametersResult.bodyEnumerationSkipped());

        HttpMessageDocSupport.putBodyFields(
                req,
                bodyBytes,
                requestHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                false,
                request.bodyOffset());

        HttpMessageDocSupport.putRequestBodyField(req, "markers", HttpMessageDocSupport.trafficMarkersToList(request.markers()));
        return req;
    }

    private static Map<String, Object> buildSitemapRequestDocStrict(HttpRequest request) {
        Map<String, Object> req = new LinkedHashMap<>();
        putRequestCoreFields(req, request.method(), request.path(), request.pathWithoutQuery(),
                request.query(), request.fileExtension(), true);

        burp.api.montoya.http.message.ContentType contentType = request.contentType();
        List<HttpHeader> requestHeaders = request.headers();
        byte[] bodyBytes = request.body() == null ? null : request.body().getBytes();
        String inferredContentType = RequestResponseParametersSupport.inferRequestContentType(bodyBytes, requestHeaders);
        req.put("header", HttpMessageDocSupport.buildRequestHeaderValueObject(requestHeaders, inferredContentType));
        req.put("parameters", RequestResponseParametersSupport.sitemapUrlParameters(request));

        HttpMessageDocSupport.putBodyFields(
                req,
                bodyBytes,
                requestHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                false,
                request.bodyOffset());

        HttpMessageDocSupport.putRequestBodyField(req, "markers", HttpMessageDocSupport.trafficMarkersToList(request.markers()));
        return req;
    }

    private static void putRequestCoreFields(
            Map<String, Object> req,
            String method,
            String pathWithQuery,
            String pathWithoutQuery,
            String query,
            String fileExtension,
            boolean trafficShape) {
        req.put("method", method);
        if (trafficShape) {
            req.put("path", TrafficRequestPathFields.from(pathWithQuery, pathWithoutQuery, query, fileExtension));
        } else {
            req.put("path", pathWithQuery);
            req.put("path_without_query", HttpMessageDocSupport.nullToEmpty(pathWithoutQuery));
            req.put("query", HttpMessageDocSupport.nullToEmpty(query));
            req.put("file_extension", HttpMessageDocSupport.nullToEmpty(fileExtension));
        }
    }

    /**
     * Resolves {@code request.path.with_query} from a traffic or legacy request sub-document.
     */
    static String requestPathWithQuery(Map<String, Object> requestDoc) {
        if (requestDoc == null) {
            return null;
        }
        Object path = requestDoc.get("path");
        if (path instanceof Map<?, ?> pathMap) {
            return HttpMessageDocSupport.stringValue(pathMap.get("with_query"));
        }
        return HttpMessageDocSupport.stringValue(path);
    }

    private static void putLegacyRequestContentTypeFields(
            Map<String, Object> req,
            burp.api.montoya.http.message.ContentType contentType,
            String inferredContentType) {
        req.put("content_type", contentType == null ? null : contentType.toString());
        req.put("content_type_enum", contentType == null ? null : contentType.name());
        req.put("inferred_content_type", inferredContentType);
    }

    /**
     * Builds a request sub-document from raw bytes when Montoya accessors throw.
     *
     * <p>The fallback preserves export continuity for malformed Repeater requests by parsing the
     * raw request line and safely querying only the accessors that Burp still exposes. Missing
     * fields remain {@code null} instead of aborting the whole document.</p>
     */
    private static Map<String, Object> buildFallbackRequestDoc(HttpRequest request, boolean trafficShape) {
        RawRequestSnapshot raw = RawRequestSnapshot.from(request);
        Map<String, Object> req = new LinkedHashMap<>();
        putRequestCoreFields(req, raw.method(), raw.path(), raw.pathWithoutQuery(), raw.query(),
                raw.fileExtension(), trafficShape);

        burp.api.montoya.http.message.ContentType contentType = safeContentType(request);
        List<HttpHeader> requestHeaders = safeHeaders(request);
        String inferredContentType = RequestResponseParametersSupport.inferRequestContentType(raw.bodyBytes(), requestHeaders);
        if (trafficShape) {
            req.put("header", HttpMessageDocSupport.buildRequestHeaderValueObject(requestHeaders, inferredContentType));
        } else {
            putLegacyRequestContentTypeFields(req, contentType, inferredContentType);
            req.put("headers", HttpMessageDocSupport.buildHeadersObject(requestHeaders));
        }
        req.put("parameters", safeParameters(request, contentType, requestHeaders, inferredContentType));

        HttpMessageDocSupport.putBodyFields(
                req,
                raw.bodyBytes(),
                requestHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                false,
                raw.bodyOffset());

        HttpMessageDocSupport.putRequestBodyField(req, "markers", safeTrafficMarkers(request));
        return req;
    }

    private static Map<String, Object> buildFallbackSitemapRequestDoc(HttpRequest request) {
        RawRequestSnapshot raw = RawRequestSnapshot.from(request);
        Map<String, Object> req = new LinkedHashMap<>();
        putRequestCoreFields(req, raw.method(), raw.path(), raw.pathWithoutQuery(), raw.query(),
                raw.fileExtension(), true);

        burp.api.montoya.http.message.ContentType contentType = safeContentType(request);
        List<HttpHeader> requestHeaders = safeHeaders(request);
        String inferredContentType = RequestResponseParametersSupport.inferRequestContentType(raw.bodyBytes(), requestHeaders);
        req.put("header", HttpMessageDocSupport.buildRequestHeaderValueObject(requestHeaders, inferredContentType));
        req.put("parameters", safeSitemapUrlParameters(request));

        HttpMessageDocSupport.putBodyFields(
                req,
                raw.bodyBytes(),
                requestHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                false,
                raw.bodyOffset());

        HttpMessageDocSupport.putRequestBodyField(req, "markers", safeTrafficMarkers(request));
        return req;
    }

    /**
     * Builds a response sub-document for findings/sitemap indices (legacy flat field names).
     */
    public static Map<String, Object> buildResponseDoc(HttpResponse response) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status_code", (int) response.statusCode());
        resp.put("status_code_class", RequestResponseParametersSupport.statusCodeClassName(response.statusCode()));
        resp.put("status_description", response.reasonPhrase());
        resp.put("http_version", safeResponseHttpVersion(response));
        putLegacyMimeFields(resp, response);
        populateResponsePayload(resp, response, false);
        return resp;
    }

    /**
     * Builds a response sub-document for the traffic index ({@code status}, {@code protocol},
     * nested {@code mime_type}, headers, body, cookies).
     */
    public static Map<String, Object> buildTrafficResponseDoc(HttpResponse response) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", TrafficResponseStatusFields.from(response));
        resp.put("protocol", TrafficProtocolFields.responseProtocol(safeResponseHttpVersion(response)));
        populateResponsePayload(resp, response, true);
        return resp;
    }

    /**
     * Empty traffic-index response used when a pair has no response yet (orphans, history rows).
     */
    public static Map<String, Object> emptyTrafficResponseDoc() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", TrafficResponseStatusFields.of(0, null, "No response"));
        response.put("protocol", TrafficProtocolFields.responseProtocol(null));
        response.put("header", TrafficResponseHeaderFields.empty());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("length", 0);
        body.put("offset", 0);
        body.put("b64", null);
        body.put("text", null);
        body.put("markers", List.of());
        response.put("body", body);
        return response;
    }

    private static void putLegacyMimeFields(Map<String, Object> resp, HttpResponse response) {
        MimeType mime = response.mimeType();
        MimeType stated = response.statedMimeType();
        MimeType inferred = response.inferredMimeType();
        resp.put("mime_type", mime == null ? null : mime.name());
        resp.put("stated_mime_type", stated == null ? null : stated.name());
        resp.put("inferred_mime_type", inferred == null ? null : inferred.name());
    }

    private static void populateResponsePayload(
            Map<String, Object> resp,
            HttpResponse response,
            boolean trafficShape) {
        List<HttpHeader> responseHeaders = response.headers();
        if (trafficShape) {
            resp.put("header", HttpMessageDocSupport.buildResponseHeaderValueObject(responseHeaders, response));
        } else {
            Map<String, Object> responseHeadersDoc = HttpMessageDocSupport.buildHeadersObject(responseHeaders);
            responseHeadersDoc.put("names", HttpMessageDocSupport.headerNames(responseHeaders));
            resp.put("headers", responseHeadersDoc);
            resp.put("cookies", HttpMessageDocSupport.cookiesToList(response.cookies()));
        }

        MimeType mime = response.mimeType();
        MimeType stated = response.statedMimeType();
        MimeType inferred = response.inferredMimeType();
        boolean montoyaTextualHint = HttpMessageDocSupport.isTextualMimeHint(mime) || HttpMessageDocSupport.isTextualMimeHint(stated) || HttpMessageDocSupport.isTextualMimeHint(inferred);
        boolean montoyaBinaryHint = HttpMessageDocSupport.isBinaryMimeHint(mime) || HttpMessageDocSupport.isBinaryMimeHint(stated) || HttpMessageDocSupport.isBinaryMimeHint(inferred);

        byte[] bodyBytes = response.body() == null ? null : response.body().getBytes();
        HttpMessageDocSupport.putBodyFields(
                resp,
                bodyBytes,
                responseHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        HttpMessageDocSupport.mimeTypeHint(mime),
                        HttpMessageDocSupport.mimeTypeHint(stated),
                        HttpMessageDocSupport.mimeTypeHint(inferred)),
                montoyaTextualHint,
                montoyaBinaryHint,
                response.bodyOffset());

        if (trafficShape) {
            HttpMessageDocSupport.putResponseBodyField(resp, "markers", HttpMessageDocSupport.trafficMarkersToList(response.markers()));
        } else {
            resp.put("markers", HttpMessageDocSupport.markersToList(response.markers()));
        }

        if (response instanceof HttpResponseReceived received) {
            putResponseAttributes(resp, received, trafficShape);
        }
    }

    static String safeResponseHttpVersion(HttpResponse response) {
        if (response == null) {
            return null;
        }
        try {
            return response.httpVersion();
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static void putResponseAttributes(
            Map<String, Object> responseDoc,
            HttpResponseReceived response,
            boolean trafficShape) {
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
            AttributeType.OUTBOUND_EDGE_TAG_NAMES
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
                String bodyField = bodyDerivedResponseField(attr.type(), trafficShape);
                Object value = attributeValue(attr);
                if (bodyField != null) {
                    if (value != null) {
                        String htmlField = trafficShape ? htmlDerivedResponseBodyField(attr.type()) : null;
                        if (htmlField != null) {
                            HttpMessageDocSupport.putResponseBodyHtmlField(responseDoc, htmlField, value);
                        } else {
                            HttpMessageDocSupport.putResponseBodyField(responseDoc, bodyField, value);
                        }
                    }
                    continue;
                }
                String headerField = trafficShape ? null : headerDerivedResponseField(attr.type());
                if (headerField != null) {
                    if (value != null) {
                        HttpMessageDocSupport.putResponseHeaderField(responseDoc, headerField, value);
                    }
                    continue;
                }
                String fieldName = attributeTypeToFieldName(attr.type());
                if (trafficShape) {
                    continue;
                }
                if (fieldName == null) {
                    continue;
                }
                if (value != null) {
                    responseDoc.put(fieldName, value);
                }
            }
        } catch (Exception e) {
            Logger.logDebug("[RequestResponseDocBuilder] response.attributes() failed: " + e.getMessage());
        }
    }

    private static String attributeTypeToFieldName(AttributeType type) {
        if (type == null) {
            return null;
        }
        return type.name().toLowerCase();
    }

    private static String bodyDerivedResponseField(AttributeType type, boolean trafficShape) {
        if (type == null) {
            return null;
        }
        return switch (type) {
            case PAGE_TITLE -> "page_title";
            case VISIBLE_TEXT -> "visible_text";
            case WORD_COUNT -> "word_count";
            case VISIBLE_WORD_COUNT -> "visible_word_count";
            case LINE_COUNT -> "line_count";
            case ANCHOR_LABELS -> "anchor_labels";
            case TAG_NAMES -> "tag_names";
            case DIV_IDS -> "div_ids";
            case CSS_CLASSES -> "css_classes";
            case BUTTON_SUBMIT_LABELS -> trafficShape ? "button_submit_labels" : null;
            case CANONICAL_LINK -> trafficShape ? "canonical_link" : null;
            case COMMENTS -> trafficShape ? "comments" : null;
            case INPUT_IMAGE_LABELS -> trafficShape ? "input_image_labels" : null;
            case INPUT_SUBMIT_LABELS -> trafficShape ? "input_submit_labels" : null;
            case NON_HIDDEN_FORM_INPUT_TYPES -> trafficShape ? "non_hidden_form_input_types" : null;
            case OUTBOUND_EDGE_COUNT -> trafficShape ? "outbound_edge_count" : null;
            case OUTBOUND_EDGE_TAG_NAMES -> trafficShape ? "outbound_edge_tag_names" : null;
            default -> null;
        };
    }

    private static String htmlDerivedResponseBodyField(AttributeType type) {
        if (type == null) {
            return null;
        }
        return switch (type) {
            case PAGE_TITLE -> "page_title";
            case VISIBLE_TEXT -> "text.visible_text";
            case VISIBLE_WORD_COUNT -> "text.visible_word_count";
            case ANCHOR_LABELS -> "links.anchor_labels";
            case CANONICAL_LINK -> "links.canonical_link";
            case OUTBOUND_EDGE_COUNT -> "links.outbound_edge_count";
            case OUTBOUND_EDGE_TAG_NAMES -> "links.outbound_edge_tag_names";
            case TAG_NAMES -> "dom.tag_names";
            case DIV_IDS -> "dom.div_ids";
            case CSS_CLASSES -> "dom.css_classes";
            case BUTTON_SUBMIT_LABELS -> "forms.button_submit_labels";
            case INPUT_IMAGE_LABELS -> "forms.input_image_labels";
            case INPUT_SUBMIT_LABELS -> "forms.input_submit_labels";
            case NON_HIDDEN_FORM_INPUT_TYPES -> "forms.non_hidden_form_input_types";
            case COMMENTS -> "comments";
            default -> null;
        };
    }

    private static String headerDerivedResponseField(AttributeType type) {
        if (type == null) {
            return null;
        }
        return switch (type) {
            case ETAG_HEADER -> "etag";
            case LAST_MODIFIED_HEADER -> "last_modified";
            case CONTENT_LOCATION -> "content_location";
            default -> null;
        };
    }


    private static Object attributeValue(Attribute attr) {
        if (attr == null) {
            return null;
        }
        return attr.value();
    }


    private static burp.api.montoya.http.message.ContentType safeContentType(HttpRequest request) {
        if (request == null) {
            return null;
        }
        try {
            return request.contentType();
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static List<HttpHeader> safeHeaders(HttpRequest request) {
        if (request == null) {
            return List.of();
        }
        try {
            List<HttpHeader> headers = request.headers();
            return headers == null ? List.of() : headers;
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    private static List<Map<String, Object>> safeParameters(
            HttpRequest request,
            burp.api.montoya.http.message.ContentType contentType,
            List<HttpHeader> headers,
            String inferredContentType) {
        if (request == null) {
            return List.of();
        }
        try {
            boolean includeBody = RequestResponseParametersSupport.shouldIncludeBodyParameters(contentType, headers, inferredContentType);
            ParametersResult result = ParametersResult.from(
                    RequestResponseParametersSupport.collectParameters(request, includeBody));
            RequestResponseParametersSupport.recordParameterTelemetry(request, contentType, result.entries().size(),
                    result.droppedSynthesized(), result.bodyEnumerationSkipped());
            return result.entries();
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    private static List<Map<String, Object>> safeSitemapUrlParameters(HttpRequest request) {
        try {
            return RequestResponseParametersSupport.sitemapUrlParameters(request);
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    private static List<Map<String, Object>> safeTrafficMarkers(HttpRequest request) {
        if (request == null) {
            return List.of();
        }
        try {
            return HttpMessageDocSupport.trafficMarkersToList(request.markers());
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    /**
     * Resolves the HTTP version for a request, including malformed requests where Montoya accessors throw.
     */
    public static String safeRequestHttpVersion(HttpRequest request) {
        if (request == null) {
            return null;
        }
        try {
            return request.httpVersion();
        } catch (RuntimeException ignored) {
            return RawRequestSnapshot.from(request).httpVersion();
        }
    }

    /**
     * Returns {@link HttpRequest#url()} when available, or {@code null} when Montoya throws.
     *
     * <p>Use this for lightweight call sites (for example scope filtering) that only need a safe
     * URL lookup without the reconstruction cost of {@link #buildBestEffortUrl}. The logged context
     * mirrors the reconstruction helper so failure reasons stay traceable across exports.</p>
     *
     * @param request request whose direct URL accessor may throw
     * @param logPrefix logger prefix without brackets, for example {@code "Sitemap"}
     * @return trimmed URL when available, otherwise {@code null}
     */
    public static String safeRequestUrl(HttpRequest request, String logPrefix) {
        try {
            return request == null ? null : HttpMessageDocSupport.normalizeBlank(request.url());
        } catch (RuntimeException e) {
            String prefix = HttpMessageDocSupport.normalizeBlank(logPrefix);
            if (prefix == null) {
                Logger.logDebug("[RequestResponseDocBuilder] Failed to resolve request URL: "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            } else {
                Logger.logDebug("[" + prefix + "] Failed to resolve request URL: "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            }
            return null;
        }
    }

    private static String portSuffix(String scheme, int port) {
        if (port <= 0) {
            return "";
        }
        if (("http".equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443)) {
            return "";
        }
        return ":" + port;
    }

    private record RawRequestSnapshot(
            String method,
            String path,
            String pathWithoutQuery,
            String query,
            String fileExtension,
            String httpVersion,
            byte[] bodyBytes,
            int bodyOffset) {
        private static RawRequestSnapshot from(HttpRequest request) {
            byte[] rawBytes = rawBytes(request);
            int bodyOffset = bodyOffset(rawBytes);
            String requestLine = requestLine(rawBytes, bodyOffset);
            String[] parts = requestLine == null ? new String[0] : requestLine.split(" ", 3);
            String method = HttpMessageDocSupport.normalizeBlank(parts.length > 0 ? parts[0] : null);
            String path = HttpMessageDocSupport.normalizeBlank(parts.length > 1 ? parts[1] : null);
            String httpVersion = HttpMessageDocSupport.normalizeBlank(parts.length > 2 ? parts[2] : null);
            return new RawRequestSnapshot(
                    method,
                    path,
                    pathWithoutQuery(path),
                    queryPart(path),
                    fileExtension(path),
                    httpVersion,
                    bodyBytes(rawBytes, bodyOffset),
                    bodyOffset);
        }

        private static byte[] rawBytes(HttpRequest request) {
            if (request == null) {
                return null;
            }
            try {
                return request.toByteArray() == null ? null : request.toByteArray().getBytes();
            } catch (RuntimeException ignored) {
                return null;
            }
        }

        private static int bodyOffset(byte[] rawBytes) {
            if (rawBytes == null || rawBytes.length == 0) {
                return 0;
            }
            for (int i = 0; i <= rawBytes.length - 4; i++) {
                if (rawBytes[i] == '\r' && rawBytes[i + 1] == '\n'
                        && rawBytes[i + 2] == '\r' && rawBytes[i + 3] == '\n') {
                    return i + 4;
                }
            }
            for (int i = 0; i <= rawBytes.length - 2; i++) {
                if (rawBytes[i] == '\n' && rawBytes[i + 1] == '\n') {
                    return i + 2;
                }
            }
            return rawBytes.length;
        }

        private static String requestLine(byte[] rawBytes, int bodyOffset) {
            if (rawBytes == null || rawBytes.length == 0) {
                return null;
            }
            int limit = Math.min(bodyOffset, rawBytes.length);
            int lineEnd = 0;
            while (lineEnd < limit && rawBytes[lineEnd] != '\r' && rawBytes[lineEnd] != '\n') {
                lineEnd++;
            }
            if (lineEnd <= 0) {
                return null;
            }
            return new String(rawBytes, 0, lineEnd, StandardCharsets.ISO_8859_1);
        }

        private static byte[] bodyBytes(byte[] rawBytes, int bodyOffset) {
            if (rawBytes == null || bodyOffset >= rawBytes.length) {
                return null;
            }
            return Arrays.copyOfRange(rawBytes, bodyOffset, rawBytes.length);
        }

        private static String pathWithoutQuery(String path) {
            if (path == null) {
                return null;
            }
            int queryIndex = path.indexOf('?');
            return queryIndex >= 0 ? path.substring(0, queryIndex) : path;
        }

        private static String queryPart(String path) {
            if (path == null) {
                return null;
            }
            int queryIndex = path.indexOf('?');
            return queryIndex >= 0 && queryIndex + 1 < path.length()
                    ? path.substring(queryIndex + 1)
                    : null;
        }

        private static String fileExtension(String path) {
            String pathWithoutQuery = pathWithoutQuery(path);
            if (pathWithoutQuery == null || pathWithoutQuery.isBlank()) {
                return null;
            }
            int slash = pathWithoutQuery.lastIndexOf('/');
            String leaf = slash >= 0 ? pathWithoutQuery.substring(slash + 1) : pathWithoutQuery;
            int dot = leaf.lastIndexOf('.');
            return dot >= 0 && dot + 1 < leaf.length() ? leaf.substring(dot + 1) : null;
        }
    }
}
