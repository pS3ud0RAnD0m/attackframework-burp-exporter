package ai.attackframework.tools.burp.sinks;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ai.attackframework.tools.burp.utils.Logger;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.core.Marker;

/**
 * Builds request and response sub-documents in the same shape as the traffic index,
 * for use by both {@link OpenSearchTrafficHandler} and {@link SitemapIndexReporter}.
 */
public final class RequestResponseDocBuilder {

    private RequestResponseDocBuilder() {}

    /**
     * Builds a request sub-document matching the traffic index request shape.
     * Body is always stored as base64 in {@code body} for exact replay; {@code body_content}
     * is set only when the body is valid UTF-8 text (for search/display).
     *
     * @param request the HTTP request (never null)
     * @return map with method, path, headers, parameters, body (base64), body_content (when text), etc.
     */
    public static Map<String, Object> buildRequestDoc(HttpRequest request) {
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
        putBodyFields(req, bodyBytes);
        req.put("body_offset", request.bodyOffset());

        req.put("markers", markersToList(request.markers()));
        return req;
    }

    /**
     * Builds a response sub-document matching the traffic index response shape.
     * Body is always stored as base64 in {@code body} for exact replay; {@code body_content}
     * is set only when the body is valid UTF-8 text. When the response is an
     * {@link HttpResponseReceived}, response attributes (page_title, location, etc.) are included.
     *
     * @param response the HTTP response (never null)
     * @return map with status, headers, cookies, body (base64), body_content (when text), etc.
     */
    public static Map<String, Object> buildResponseDoc(HttpResponse response) {
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
        putBodyFields(resp, bodyBytes);
        resp.put("body_offset", response.bodyOffset());

        resp.put("markers", markersToList(response.markers()));

        if (response instanceof HttpResponseReceived received) {
            putResponseAttributes(resp, received);
        }
        return resp;
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
            Logger.logDebug("[RequestResponseDocBuilder] response.attributes() failed: " + e.getMessage());
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
        return attr.value();
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
            entry.put("expiration", exp == null || exp.isEmpty() ? null : exp.get().toInstant().toString());
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

    /**
     * Puts body_length, body (base64 for exact replay of any type), and body_content (only when valid UTF-8 text).
     */
    private static void putBodyFields(Map<String, Object> doc, byte[] bodyBytes) {
        int bodyLen = bodyBytes == null ? 0 : bodyBytes.length;
        doc.put("body_length", bodyLen);
        if (bodyBytes != null && bodyBytes.length > 0) {
            doc.put("body", Base64.getEncoder().encodeToString(bodyBytes));
            String text = decodeUtf8OrNull(bodyBytes);
            doc.put("body_content", text);
        } else {
            doc.put("body", null);
            doc.put("body_content", null);
        }
    }

    /** Returns the body as a string when it is valid UTF-8; otherwise null (e.g. binary content). */
    private static String decodeUtf8OrNull(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(body)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    /**
     * Converts Burp headers to a list of name/value maps for the traffic/sitemap index mapping.
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
