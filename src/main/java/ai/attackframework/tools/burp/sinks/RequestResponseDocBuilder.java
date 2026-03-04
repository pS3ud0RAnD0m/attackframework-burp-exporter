package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;

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

    private static final int TEXT_SNIFF_BYTES = 64 * 1024;
    private static final double MAX_CONTROL_CHAR_RATIO = 0.02d;
    private static final Set<String> EXPLICIT_TEXTUAL_APPLICATION_TYPES = Set.of(
            "application/json",
            "application/xml",
            "application/xhtml+xml",
            "application/javascript",
            "application/ecmascript",
            "application/graphql",
            "application/sql",
            "application/x-www-form-urlencoded",
            "application/ld+json",
            "application/hal+json",
            "application/problem+json",
            "application/activity+json",
            // common custom server-side textual types seen in web/pentest traffic
            "application/php",
            "application/php3",
            "application/php4",
            "application/php5",
            "application/php6",
            "application/php7",
            "application/phtml",
            "application/phpt",
            "application/pht",
            "application/asp",
            "application/aspx",
            "application/jsp",
            "application/jspf",
            "application/jspx",
            "application/cfm",
            "application/cfml",
            "application/cfc",
            "application/cgi",
            "application/pl",
            "application/pm"
    );

    /**
     * Builds a request sub-document matching the traffic index request shape.
     * Body is always stored as base64 in {@code body.b64} for exact replay.
     *
     * @param request the HTTP request (never null)
     * @return map with method, path, headers, parameters, and body content fields.
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

        List<HttpHeader> requestHeaders = request.headers();
        req.put("headers", buildHeadersObject(requestHeaders));
        req.put("parameters", parametersToList(request.parameters()));

        byte[] bodyBytes = request.body() == null ? null : request.body().getBytes();
        putBodyFields(
                req,
                bodyBytes,
                requestHeaders,
                mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                false,
                request.bodyOffset());

        req.put("markers", markersToList(request.markers()));
        return req;
    }

    /**
     * Builds a response sub-document matching the traffic index response shape.
     * Body is always stored as base64 in {@code body.b64} for exact replay.
     * When the response is an {@link HttpResponseReceived}, response attributes
     * (page_title, location, etc.) are included.
     *
     * @param response the HTTP response (never null)
     * @return map with status, headers, cookies, and body content fields.
     */
    public static Map<String, Object> buildResponseDoc(HttpResponse response) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", (int) response.statusCode());
        resp.put("status_code_class", statusCodeClassName(response.statusCode()));
        resp.put("reason_phrase", response.reasonPhrase());
        resp.put("http_version", response.httpVersion());
        List<HttpHeader> responseHeaders = response.headers();
        Map<String, Object> responseHeadersDoc = buildHeadersObject(responseHeaders);
        responseHeadersDoc.put("names", headerNames(responseHeaders));
        resp.put("headers", responseHeadersDoc);
        resp.put("cookies", cookiesToList(response.cookies()));

        MimeType mime = response.mimeType();
        MimeType stated = response.statedMimeType();
        MimeType inferred = response.inferredMimeType();
        resp.put("mime_type", mime == null ? null : mime.name());
        resp.put("stated_mime_type", stated == null ? null : stated.name());
        resp.put("inferred_mime_type", inferred == null ? null : inferred.name());

        boolean montoyaTextualHint = isTextualMimeHint(mime) || isTextualMimeHint(stated) || isTextualMimeHint(inferred);
        boolean montoyaBinaryHint = isBinaryMimeHint(mime) || isBinaryMimeHint(stated) || isBinaryMimeHint(inferred);

        byte[] bodyBytes = response.body() == null ? null : response.body().getBytes();
        putBodyFields(
                resp,
                bodyBytes,
                responseHeaders,
                mediaTypeHints(
                        mimeTypeHint(mime),
                        mimeTypeHint(stated),
                        mimeTypeHint(inferred)),
                montoyaTextualHint,
                montoyaBinaryHint,
                response.bodyOffset());

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
                String bodyField = bodyDerivedResponseField(attr.type());
                Object value = attributeValue(attr);
                if (bodyField != null) {
                    if (value != null) {
                        putResponseBodyField(responseDoc, bodyField, value);
                    }
                    continue;
                }
                String headerField = headerDerivedResponseField(attr.type());
                if (headerField != null) {
                    if (value != null) {
                        putResponseHeaderField(responseDoc, headerField, value);
                    }
                    continue;
                }
                String fieldName = attributeTypeToFieldName(attr.type());
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

    private static String bodyDerivedResponseField(AttributeType type) {
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

    @SuppressWarnings("unchecked")
    private static void putResponseBodyField(Map<String, Object> responseDoc, String field, Object value) {
        if (responseDoc == null || field == null) {
            return;
        }
        Object bodyObj = responseDoc.get("body");
        Map<String, Object> body;
        if (bodyObj instanceof Map<?, ?>) {
            body = (Map<String, Object>) bodyObj;
        } else {
            body = new LinkedHashMap<>();
            responseDoc.put("body", body);
        }
        body.put(field, value);
    }

    @SuppressWarnings("unchecked")
    private static void putResponseHeaderField(Map<String, Object> responseDoc, String field, Object value) {
        if (responseDoc == null || field == null) {
            return;
        }
        Object headersObj = responseDoc.get("headers");
        Map<String, Object> headers;
        if (headersObj instanceof Map<?, ?>) {
            headers = (Map<String, Object>) headersObj;
        } else {
            headers = new LinkedHashMap<>();
            headers.put("full", List.of());
            responseDoc.put("headers", headers);
        }
        headers.put(field, value);
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
     * Puts body object:
     * - body.length/body.offset: raw body metadata
     * - body.b64: full raw bytes as base64 (always when body exists)
     * - body.text: only when content is dynamically classified as searchable text.
     */
    private static void putBodyFields(
            Map<String, Object> doc,
            byte[] bodyBytes,
            List<HttpHeader> headers,
            List<String> mediaTypeHints,
            boolean montoyaTextualHint,
            boolean montoyaBinaryHint,
            int bodyOffset) {
        int bodyLen = bodyBytes == null ? 0 : bodyBytes.length;
        Map<String, Object> bodyContent = new LinkedHashMap<>(4);
        bodyContent.put("length", bodyLen);
        bodyContent.put("offset", bodyOffset);
        if (bodyBytes != null && bodyBytes.length > 0) {
            bodyContent.put("b64", Base64.getEncoder().encodeToString(bodyBytes));
            bodyContent.put("text", extractBodyText(bodyBytes, headers, mediaTypeHints, montoyaTextualHint, montoyaBinaryHint));
        } else {
            bodyContent.put("b64", null);
            bodyContent.put("text", null);
        }
        doc.put("body", bodyContent);
    }

    private static String extractBodyText(
            byte[] bodyBytes,
            List<HttpHeader> headers,
            List<String> mediaTypeHints,
            boolean montoyaTextualHint,
            boolean montoyaBinaryHint) {
        if (bodyBytes == null || bodyBytes.length == 0) {
            return null;
        }
        if (hasCompressedContentEncoding(headers)) {
            return null;
        }
        String contentTypeHeader = headerValue(headers, "Content-Type");
        String mediaType = primaryMediaType(contentTypeHeader, mediaTypeHints);
        Charset charset = charsetFromContentType(contentTypeHeader);

        if (isExplicitlyBinaryMediaType(mediaType) || montoyaBinaryHint) {
            return null;
        }

        if (isTextualMediaType(mediaType) || montoyaTextualHint) {
            return decodeTextWithFallback(bodyBytes, charset);
        }

        // Unknown/rare custom media types: fall back to byte-level text sniffing.
        if (looksLikeTextPayload(bodyBytes, charset)) {
            return decodeTextWithFallback(bodyBytes, charset);
        }
        return null;
    }

    private static String primaryMediaType(String contentTypeHeader, List<String> mediaTypeHints) {
        String fromHeader = mediaType(contentTypeHeader, null);
        if (fromHeader != null) {
            return fromHeader;
        }
        if (mediaTypeHints == null || mediaTypeHints.isEmpty()) {
            return null;
        }
        for (String hint : mediaTypeHints) {
            String parsed = mediaType(null, hint);
            if (parsed != null) {
                return parsed;
            }
        }
        return null;
    }

    private static List<String> mediaTypeHints(String... hints) {
        if (hints == null || hints.length == 0) {
            return List.of();
        }
        List<String> out = new ArrayList<>(hints.length);
        for (String h : hints) {
            if (h != null && !h.isBlank()) {
                out.add(h);
            }
        }
        return out;
    }

    private static boolean hasCompressedContentEncoding(List<HttpHeader> headers) {
        String enc = headerValue(headers, "Content-Encoding");
        if (enc == null || enc.isBlank()) {
            return false;
        }
        String[] parts = enc.toLowerCase(Locale.ROOT).split(",");
        for (String p : parts) {
            String token = p.trim();
            if (token.equals("gzip") || token.equals("br") || token.equals("deflate")
                    || token.equals("compress") || token.equals("zstd")) {
                return true;
            }
        }
        return false;
    }

    private static String headerValue(List<HttpHeader> headers, String name) {
        if (headers == null || headers.isEmpty() || name == null) {
            return null;
        }
        for (HttpHeader h : headers) {
            if (h != null && h.name() != null && h.name().equalsIgnoreCase(name)) {
                return h.value();
            }
        }
        return null;
    }

    private static String mediaType(String contentTypeHeader, String contentTypeHint) {
        String candidate = contentTypeHeader;
        if (candidate == null || candidate.isBlank()) {
            candidate = contentTypeHint;
        }
        if (candidate == null || candidate.isBlank()) {
            return null;
        }
        String normalized = candidate.toLowerCase(Locale.ROOT).trim();
        int semicolon = normalized.indexOf(';');
        if (semicolon >= 0) {
            normalized = normalized.substring(0, semicolon).trim();
        }
        if (normalized.contains("/")) {
            return normalized;
        }
        // Fallback for MimeType enum-style hints when Content-Type header is absent.
        return switch (normalized) {
            case "html" -> "text/html";
            case "json" -> "application/json";
            case "xml" -> "application/xml";
            case "css" -> "text/css";
            case "javascript", "js" -> "application/javascript";
            case "plain_text", "text", "txt" -> "text/plain";
            default -> null;
        };
    }

    private static boolean isTextualMediaType(String mediaType) {
        if (mediaType == null || mediaType.isBlank()) {
            return false;
        }
        if (mediaType.startsWith("text/")) {
            return true;
        }
        if (mediaType.startsWith("message/")) {
            return true;
        }
        if (mediaType.endsWith("+json") || mediaType.endsWith("+xml")) {
            return true;
        }
        if (EXPLICIT_TEXTUAL_APPLICATION_TYPES.contains(mediaType)) {
            return true;
        }

        // textual application/* subtype hints (broad but still bounded by binary deny-list)
        if (mediaType.startsWith("application/")) {
            return mediaType.contains("json")
                    || mediaType.contains("xml")
                    || mediaType.contains("yaml")
                    || mediaType.contains("yml")
                    || mediaType.contains("csv")
                    || mediaType.contains("javascript")
                    || mediaType.contains("ecmascript")
                    || mediaType.contains("xhtml")
                    || mediaType.contains("sql")
                    || mediaType.contains("graphql")
                    || mediaType.contains("urlencoded")
                    || mediaType.contains("www-form-urlencoded");
        }
        return false;
    }

    private static boolean isExplicitlyBinaryMediaType(String mediaType) {
        if (mediaType == null || mediaType.isBlank()) {
            return false;
        }
        if (mediaType.startsWith("image/")
                || mediaType.startsWith("audio/")
                || mediaType.startsWith("video/")
                || mediaType.startsWith("font/")
                || mediaType.startsWith("model/")
                || mediaType.startsWith("multipart/")) {
            return true;
        }
        if (mediaType.startsWith("application/")) {
            return mediaType.equals("application/octet-stream")
                    || mediaType.equals("application/pdf")
                    || mediaType.equals("application/zip")
                    || mediaType.equals("application/gzip")
                    || mediaType.equals("application/zstd")
                    || mediaType.equals("application/x-gzip")
                    || mediaType.equals("application/x-brotli")
                    || mediaType.equals("application/vnd.ms-fontobject")
                    || mediaType.contains("protobuf")
                    || mediaType.contains("pkcs")
                    || mediaType.contains("font")
                    || mediaType.contains("zip")
                    || mediaType.contains("gzip")
                    || mediaType.contains("tar")
                    || mediaType.contains("rar")
                    || mediaType.contains("7z");
        }
        return false;
    }

    private static boolean looksLikeTextPayload(byte[] bodyBytes, Charset charsetHint) {
        int n = Math.min(bodyBytes.length, TEXT_SNIFF_BYTES);
        if (n <= 0) {
            return false;
        }
        byte[] sample = new byte[n];
        System.arraycopy(bodyBytes, 0, sample, 0, n);
        if (containsNul(sample)) {
            return false;
        }
        String decoded = decodeTextWithFallback(sample, charsetHint);
        return decoded != null && hasLowControlCharacterRatio(decoded);
    }

    private static boolean containsNul(byte[] data) {
        for (byte b : data) {
            if (b == 0x00) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasLowControlCharacterRatio(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        int control = 0;
        int total = text.length();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t' && c != '\f') {
                control++;
            }
        }
        return ((double) control / (double) total) <= MAX_CONTROL_CHAR_RATIO;
    }

    private static String decodeTextWithFallback(byte[] bodyBytes, Charset preferred) {
        if (bodyBytes == null || bodyBytes.length == 0) {
            return null;
        }
        if (preferred != null) {
            String text = decodeBytes(bodyBytes, preferred);
            if (text != null) {
                return text;
            }
        }
        String utf8 = decodeBytes(bodyBytes, StandardCharsets.UTF_8);
        if (utf8 != null) {
            return utf8;
        }
        return decodeBytes(bodyBytes, StandardCharsets.ISO_8859_1);
    }

    private static Charset charsetFromContentType(String contentTypeHeader) {
        if (contentTypeHeader == null || contentTypeHeader.isBlank()) {
            return null;
        }
        String[] parts = contentTypeHeader.split(";");
        for (int i = 1; i < parts.length; i++) {
            String p = parts[i].trim();
            if (p.toLowerCase(Locale.ROOT).startsWith("charset=")) {
                String cs = p.substring("charset=".length()).trim();
                if (cs.startsWith("\"") && cs.endsWith("\"") && cs.length() >= 2) {
                    cs = cs.substring(1, cs.length() - 1);
                }
                try {
                    return Charset.forName(cs);
                } catch (IllegalCharsetNameException | UnsupportedCharsetException ex) {
                    return null;
                }
            }
        }
        return null;
    }

    private static String mimeTypeHint(MimeType mimeType) {
        if (mimeType == null) {
            return null;
        }
        return mimeType.name();
    }

    private static boolean isTextualMimeHint(MimeType mimeType) {
        if (mimeType == null) {
            return false;
        }
        String n = mimeType.name().toLowerCase(Locale.ROOT);
        return n.contains("text")
                || n.contains("html")
                || n.contains("xml")
                || n.contains("json")
                || n.contains("css")
                || n.contains("javascript")
                || n.contains("script");
    }

    private static boolean isBinaryMimeHint(MimeType mimeType) {
        if (mimeType == null) {
            return false;
        }
        String n = mimeType.name().toLowerCase(Locale.ROOT);
        return n.contains("image")
                || n.contains("audio")
                || n.contains("video")
                || n.contains("font")
                || n.contains("binary")
                || n.contains("pdf")
                || n.contains("octet");
    }

    private static String decodeBytes(byte[] bodyBytes, Charset charset) {
        try {
            CharsetDecoder decoder = charset.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            return decoder.decode(ByteBuffer.wrap(bodyBytes)).toString();
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

    private static Map<String, Object> buildHeadersObject(List<HttpHeader> headers) {
        Map<String, Object> out = new LinkedHashMap<>(1);
        out.put("full", headersToList(headers));
        return out;
    }

    private static List<String> headerNames(List<HttpHeader> headers) {
        if (headers == null || headers.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>(headers.size());
        for (HttpHeader h : headers) {
            if (h != null && h.name() != null) {
                out.add(h.name());
            }
        }
        return out;
    }
}
