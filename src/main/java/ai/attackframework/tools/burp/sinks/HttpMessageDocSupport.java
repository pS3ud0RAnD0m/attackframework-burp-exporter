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

import ai.attackframework.tools.burp.utils.StringKeyedMaps;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.responses.HttpResponse;

/** Shared HTTP message encoding, headers, markers, and body fields. */
final class HttpMessageDocSupport {

    private HttpMessageDocSupport() {}

    static final int TEXT_SNIFF_BYTES = 64 * 1024;
    static final double MAX_CONTROL_CHAR_RATIO = 0.02d;
    /**
     * Inference vocabulary for {@code request.header.content-type_inferred}.
     *
     * <p>Mirrors the fidelity pattern used by {@code response.header.content-type_inferred_burp_body}
     * (Burp's byte-sniffing verdict) so consumers can compare declared vs. sniffed without us ever
     * rewriting the declared value. Feeds {@link #shouldIncludeBodyParameters} as a
     * tamper-resistant gate against Content-Type spoofing, e.g. a raw protobuf body declared
     * as {@code application/x-www-form-urlencoded}.</p>
     */
    static final String INFERRED_CT_EMPTY = "empty";
    static final String INFERRED_CT_BINARY = "binary";
    static final String INFERRED_CT_JSON = "json";
    static final String INFERRED_CT_XML = "xml";
    static final String INFERRED_CT_MULTIPART = "multipart";
    static final String INFERRED_CT_TEXT = "text";
    static final Set<String> EXPLICIT_TEXTUAL_APPLICATION_TYPES = Set.of(
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
    static void putResponseBodyField(Map<String, Object> responseDoc, String field, Object value) {
        if (responseDoc == null || field == null) {
            return;
        }
        Map<String, Object> body = StringKeyedMaps.nested(responseDoc, "body", LinkedHashMap::new);
        body.put(field, value);
    }

    static void putResponseBodyHtmlField(Map<String, Object> responseDoc, String field, Object value) {
        if (responseDoc == null || field == null) {
            return;
        }
        Map<String, Object> body = StringKeyedMaps.nested(responseDoc, "body", LinkedHashMap::new);
        Map<String, Object> html = StringKeyedMaps.nested(body, "html", LinkedHashMap::new);
        int separator = field.indexOf('.');
        if (separator < 0) {
            html.put(field, value);
            return;
        }
        String sectionName = field.substring(0, separator);
        String leaf = field.substring(separator + 1);
        if (sectionName.isBlank() || leaf.isBlank()) {
            return;
        }
        Map<String, Object> section = StringKeyedMaps.nested(html, sectionName, LinkedHashMap::new);
        section.put(leaf, value);
    }

    static void putRequestBodyField(Map<String, Object> requestDoc, String field, Object value) {
        if (requestDoc == null || field == null) {
            return;
        }
        Map<String, Object> body = StringKeyedMaps.nested(requestDoc, "body", LinkedHashMap::new);
        body.put(field, value);
    }

    static void putResponseHeaderField(Map<String, Object> responseDoc, String field, Object value) {
        if (responseDoc == null || field == null) {
            return;
        }
        Map<String, Object> headers = StringKeyedMaps.nested(responseDoc, "headers", () -> {
            Map<String, Object> fresh = new LinkedHashMap<>();
            fresh.put("full", List.of());
            return fresh;
        });
        headers.put(field, value);
    }

    static List<Map<String, Object>> cookiesToList(List<Cookie> cookies) {
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

    /**
     * Converts a list of Burp {@link Marker} ranges into the public marker map shape used
     * across the request/response document. Intended for callers (such as
     * {@code FindingsIndexReporter}) that need to inject pair-level scanner markers
     * obtained from {@code HttpRequestResponse.requestMarkers() / responseMarkers()} in
     * place of (or in addition to) per-message {@code request.markers() / response.markers()}.
     *
     * <p>Null and empty inputs return an empty immutable list. Entries with a null
     * {@code range()} are skipped to mirror the internal builder behavior.</p>
     */
    public static List<Map<String, Object>> convertMarkersToList(List<Marker> markers) {
        return markersToList(markers);
    }

    /**
     * Converts pair-level issue evidence markers to the traffic HTTP marker shape.
     */
    public static List<Map<String, Object>> convertTrafficMarkersToList(List<Marker> markers) {
        return trafficMarkersToList(markers);
    }

    static List<Map<String, Object>> markersToList(List<Marker> markers) {
        return markersToList(markers, false);
    }

    static List<Map<String, Object>> trafficMarkersToList(List<Marker> markers) {
        return markersToList(markers, true);
    }

    static List<Map<String, Object>> markersToList(List<Marker> markers, boolean trafficShape) {
        if (markers == null || markers.isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> out = new ArrayList<>(markers.size());
        for (Marker m : markers) {
            if (m == null || m.range() == null) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>(2);
            if (trafficShape) {
                entry.put("start_inclusive", m.range().startIndexInclusive());
                entry.put("end_exclusive", m.range().endIndexExclusive());
            } else {
                entry.put("start_index_inclusive", m.range().startIndexInclusive());
                entry.put("end_index_exclusive", m.range().endIndexExclusive());
            }
            out.add(entry);
        }
        return out;
    }

    /**
     * Puts body object:
     * <ul>
     *   <li>{@code body.length}/{@code body.offset}: on-the-wire body metadata</li>
     *   <li>{@code body.b64}: full wire bytes as base64 (always when body exists)</li>
     *   <li>{@code body.text}: charset-decoded string after Content-Encoding removal (when applicable);
     *       {@code null} when the payload stays binary</li>
     * </ul>
     */
    static void putBodyFields(
            Map<String, Object> doc,
            byte[] bodyBytes,
            List<HttpHeader> headers,
            List<String> mediaTypeHints,
            boolean montoyaTextualHint,
            int bodyOffset) {
        putBodyFields(
                doc,
                bodyBytes,
                headers,
                mediaTypeHints,
                montoyaTextualHint,
                bodyOffset,
                true);
    }

    /**
     * Puts the body object, optionally allowing gzip-magic sniff for declared form/multipart bodies
     * without a {@code Content-Encoding} header (request-only heuristic).
     */
    static void putBodyFields(
            Map<String, Object> doc,
            byte[] bodyBytes,
            List<HttpHeader> headers,
            List<String> mediaTypeHints,
            boolean montoyaTextualHint,
            int bodyOffset,
            boolean allowDeclaredFormGzipSniff) {
        doc.put(
                "body",
                buildBodyContent(
                        bodyBytes,
                        headers,
                        mediaTypeHints,
                        montoyaTextualHint,
                        bodyOffset,
                        allowDeclaredFormGzipSniff));
    }

    static Map<String, Object> buildBodyContent(
            byte[] wireBytes,
            List<HttpHeader> headers,
            List<String> mediaTypeHints,
            boolean montoyaTextualHint,
            int bodyOffset,
            boolean allowDeclaredFormGzipSniff) {
        int bodyLen = wireBytes == null ? 0 : wireBytes.length;
        Map<String, Object> bodyContent = new LinkedHashMap<>(8);
        bodyContent.put("length", bodyLen);
        bodyContent.put("offset", bodyOffset);
        if (wireBytes == null || wireBytes.length == 0) {
            bodyContent.put("b64", null);
            bodyContent.put("text", null);
            return bodyContent;
        }
        bodyContent.put("b64", Base64.getEncoder().encodeToString(wireBytes));
        String contentTypeHeader = headerValue(headers, "Content-Type");
        String mediaType = primaryMediaType(contentTypeHeader, mediaTypeHints);
        boolean declaredForm = isDeclaredFormMediaType(mediaType, mediaTypeHints);
        BodyContentEncodingSupport.ResolvedBody resolved = BodyContentEncodingSupport.resolveForExport(
                wireBytes,
                headers,
                mediaType,
                declaredForm,
                allowDeclaredFormGzipSniff);
        bodyContent.put(
                "text",
                decodeHumanReadableBodyText(
                        resolved.logicalBytes(),
                        contentTypeHeader,
                        mediaType,
                        montoyaTextualHint));
        return bodyContent;
    }

    static String extractBodyText(
            byte[] bodyBytes,
            List<HttpHeader> headers,
            List<String> mediaTypeHints,
            boolean montoyaTextualHint) {
        if (bodyBytes == null || bodyBytes.length == 0) {
            return null;
        }
        String contentTypeHeader = headerValue(headers, "Content-Type");
        String mediaType = primaryMediaType(contentTypeHeader, mediaTypeHints);
        boolean declaredForm = isDeclaredFormMediaType(mediaType, mediaTypeHints);
        byte[] logicalBytes = BodyContentEncodingSupport.resolveForExport(
                        bodyBytes, headers, mediaType, declaredForm, true)
                .logicalBytes();
        return decodeHumanReadableBodyText(
                logicalBytes, contentTypeHeader, mediaType, montoyaTextualHint);
    }

    private static String decodeHumanReadableBodyText(
            byte[] logicalBytes,
            String contentTypeHeader,
            String mediaType,
            boolean montoyaTextualHint) {
        if (logicalBytes == null || logicalBytes.length == 0) {
            return null;
        }
        Charset charset = charsetFromContentType(contentTypeHeader);

        if (isNeverAgentTextMediaType(mediaType)) {
            return null;
        }

        if (isTextualMediaType(mediaType)
                || (montoyaTextualHint && !isExplicitlyBinaryMediaType(mediaType))) {
            return decodeTextWithFallback(logicalBytes, charset);
        }

        if (isMultipartMediaType(mediaType)) {
            return decodeTextWithFallback(logicalBytes, charset);
        }

        if (looksLikeTextPayload(logicalBytes, charset)) {
            return decodeTextWithFallback(logicalBytes, charset);
        }
        return null;
    }

    static boolean isMultipartMediaType(String mediaType) {
        return mediaType != null && mediaType.startsWith("multipart/");
    }

    /**
     * Media families that are not exported as {@code body.text} even when bytes sniff as text.
     */
    static boolean isNeverAgentTextMediaType(String mediaType) {
        if (mediaType == null || mediaType.isBlank()) {
            return false;
        }
        return mediaType.startsWith("image/")
                || mediaType.startsWith("audio/")
                || mediaType.startsWith("video/")
                || mediaType.startsWith("font/")
                || mediaType.startsWith("model/");
    }

    private static boolean isDeclaredFormMediaType(String mediaType, List<String> mediaTypeHints) {
        if (mediaType != null) {
            if (mediaType.contains("urlencoded")
                    || mediaType.contains("www-form-urlencoded")
                    || mediaType.startsWith("multipart/")) {
                return true;
            }
        }
        if (mediaTypeHints == null || mediaTypeHints.isEmpty()) {
            return false;
        }
        for (String hint : mediaTypeHints) {
            if (hint == null) {
                continue;
            }
            if ("URL_ENCODED".equals(hint) || "MULTIPART".equals(hint)) {
                return true;
            }
        }
        return false;
    }

    static String primaryMediaType(String contentTypeHeader, List<String> mediaTypeHints) {
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

    static List<String> mediaTypeHints(String... hints) {
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

    static boolean hasCompressedContentEncoding(List<HttpHeader> headers) {
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

    static String headerValue(List<HttpHeader> headers, String name) {
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

    static String mediaType(String contentTypeHeader, String contentTypeHint) {
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

    static boolean isTextualMediaType(String mediaType) {
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

    static boolean isExplicitlyBinaryMediaType(String mediaType) {
        if (mediaType == null || mediaType.isBlank()) {
            return false;
        }
        if (mediaType.startsWith("image/")
                || mediaType.startsWith("audio/")
                || mediaType.startsWith("video/")
                || mediaType.startsWith("font/")
                || mediaType.startsWith("model/")) {
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
                    || mediaType.contains("grpc")
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

    static boolean looksLikeTextPayload(byte[] bodyBytes, Charset charsetHint) {
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

    static boolean containsNul(byte[] data) {
        for (byte b : data) {
            if (b == 0x00) {
                return true;
            }
        }
        return false;
    }

    static boolean hasLowControlCharacterRatio(String text) {
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

    static String decodeTextWithFallback(byte[] bodyBytes, Charset preferred) {
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

    static Charset charsetFromContentType(String contentTypeHeader) {
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

    static String mimeTypeHint(MimeType mimeType) {
        if (mimeType == null) {
            return null;
        }
        return mimeType.name();
    }

    static boolean isTextualMimeHint(MimeType mimeType) {
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

    static boolean isBinaryMimeHint(MimeType mimeType) {
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

    static String decodeBytes(byte[] bodyBytes, Charset charset) {
        try {
            CharsetDecoder decoder = charset.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            return decoder.decode(ByteBuffer.wrap(bodyBytes)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    static String stringValue(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    static String normalizeBlank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    /**
     * Converts Burp headers to a list of name/value maps for the traffic/sitemap index mapping.
     */
    static List<Map<String, String>> headersToList(List<HttpHeader> headers) {
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

    static Map<String, Object> buildHeadersObject(List<HttpHeader> headers) {
        Map<String, Object> out = new LinkedHashMap<>(1);
        out.put("full", headersToList(headers));
        return out;
    }

    static Map<String, Object> buildHeaderValueObject(List<HttpHeader> headers) {
        if (headers == null || headers.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (HttpHeader header : headers) {
            if (header == null) {
                continue;
            }
            String name = normalizedHeaderFieldName(header.name());
            if (name == null) {
                continue;
            }
            putHeaderValue(out, name, header.value());
        }
        return out;
    }

    static Map<String, Object> buildRequestHeaderValueObject(List<HttpHeader> headers, String inferredContentType) {
        Map<String, Object> out = new LinkedHashMap<>(buildHeaderValueObject(headers));
        out.put("content-type_inferred", inferredContentType);
        return out;
    }

    static Map<String, Object> buildResponseHeaderValueObject(List<HttpHeader> headers, HttpResponse response) {
        Map<String, Object> out = new LinkedHashMap<>(buildHeaderValueObject(headers));
        TrafficResponseHeaderFields.putInferredContentTypeFields(out, response);
        return out;
    }

    static String normalizedHeaderFieldName(String headerName) {
        if (headerName == null) {
            return null;
        }
        String normalized = headerName.trim().toLowerCase(Locale.ROOT).replace('.', '_');
        return normalized.isBlank() ? null : normalized;
    }

    static void putHeaderValue(Map<String, Object> headers, String name, String value) {
        Object existing = headers.get(name);
        if (!headers.containsKey(name)) {
            headers.put(name, value);
            return;
        }
        if (existing instanceof List<?> existingValues) {
            List<Object> values = new ArrayList<>(existingValues);
            values.add(value);
            headers.put(name, values);
            return;
        }
        List<Object> values = new ArrayList<>(2);
        values.add(existing);
        values.add(value);
        headers.put(name, values);
    }

    static List<String> headerNames(List<HttpHeader> headers) {
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
