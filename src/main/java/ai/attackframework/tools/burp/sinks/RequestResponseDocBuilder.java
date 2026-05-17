package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;

import ai.attackframework.tools.burp.utils.Logger;
import burp.api.montoya.http.HttpService;
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
 * for use by both {@link TrafficHttpHandler} and {@link SitemapIndexReporter}.
 */
public final class RequestResponseDocBuilder {

    private RequestResponseDocBuilder() {}

    private static final int TEXT_SNIFF_BYTES = 64 * 1024;
    private static final double MAX_CONTROL_CHAR_RATIO = 0.02d;
    /**
     * High-cardinality alerting threshold for {@code request.parameters}.
     *
     * <p>Two distinct signals can cross this threshold for a single request, each with its
     * own log level:</p>
     * <ul>
     *   <li>{@code retained >= threshold} is a real anomaly - a legitimate request genuinely
     *       has thousands of parameters and an operator should look at it. This emits a
     *       {@code WARN} line.</li>
     *   <li>{@code droppedSynthesized >= threshold} with {@code retained} below the threshold
     *       is routine Content-Type-mismatch activity - the request declared a form-encoded
     *       Content-Type but carried a binary body, so Burp's parameter parser fabricated
     *       synthetic {@code BODY} entries from the raw bytes and our synthetic-BODY filter
     *       dropped them. This is expected behaviour on every protobuf, gRPC, or other binary
     *       request body mis-declared as form-encoded, and emits a single {@code DEBUG} line
     *       so the logs do not confuse operators with noise that looks like a warning.</li>
     * </ul>
     * <p>The {@code Synthesized Body Params Dropped} and {@code Docs Over Param Threshold}
     * counters on the Stats panel always increment regardless of log level, so dashboard
     * visibility is preserved independently of the console/file log output.</p>
     */
    static final int PARAMETERS_WARN_THRESHOLD = 5_000;
    /**
     * Hard cap on the number of parameter entries retained per request, regardless of
     * Content-Type classification.
     *
     * <p>Backstop for the case where the stated Content-Type cannot be trusted - for example a
     * raw protobuf upload declared as {@code application/x-www-form-urlencoded}, where Burp's
     * {@code HttpRequest.parameters()} synthesizes tens or hundreds of thousands of spurious
     * {@link HttpParameterType#BODY} entries. When the input exceeds this cap the builder first
     * drops all BODY entries (they are almost always the noise source and raw bytes remain in
     * {@code body.b64}), then truncates any remaining excess. Real URL-encoded forms do not
     * approach this cap, so legitimate traffic is unaffected.</p>
     */
    static final int PARAMETERS_HARD_CAP = 1_000;
    private static final int PARAMETERS_WARN_URL_MAX_LEN = 200;

    /**
     * Inference vocabulary for {@code request.inferred_content_type}.
     *
     * <p>Mirrors the fidelity pattern used by {@code response.inferred_mime_type} (Burp's
     * byte-sniffing verdict) so consumers can compare declared vs. sniffed without us ever
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
     *
     * <p>Body bytes are always stored as full base64 in {@code body.b64} for exact replay. When
     * the payload is classified as textual, {@code body.text} contains the full decoded text.</p>
     *
     * @param request the HTTP request (never null)
     * @return map with method, path, headers, parameters, and body content fields.
     */
    public static Map<String, Object> buildRequestDoc(HttpRequest request) {
        if (request == null) {
            return buildFallbackRequestDoc(null);
        }
        try {
            return buildRequestDocStrict(request);
        } catch (RuntimeException e) {
            Logger.logDebug("[RequestResponseDocBuilder] request fallback due to malformed request: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return buildFallbackRequestDoc(request);
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
     * @param requestDoc already-built request sub-document, usually from {@link #buildRequestDoc(HttpRequest)}
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
        String path = normalizeBlank(stringValue(requestDoc == null ? null : requestDoc.get("path")));
        if (path == null) {
            return null;
        }
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return path;
        }
        if (service == null || normalizeBlank(service.host()) == null) {
            return null;
        }
        String scheme = service.secure() ? "https" : "http";
        String normalizedPath = path.startsWith("/") ? path : "/" + path;
        return scheme + "://" + service.host() + portSuffix(scheme, service.port()) + normalizedPath;
    }

    private static Map<String, Object> buildRequestDocStrict(HttpRequest request) {
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
        byte[] bodyBytes = request.body() == null ? null : request.body().getBytes();
        String inferredContentType = inferRequestContentType(bodyBytes, requestHeaders);
        req.put("inferred_content_type", inferredContentType);
        req.put("headers", buildHeadersObject(requestHeaders));
        boolean includeBody = shouldIncludeBodyParameters(contentType, requestHeaders, inferredContentType);
        ParametersResult parametersResult = collectParameters(request, includeBody);
        req.put("parameters", parametersResult.entries());
        recordParameterTelemetry(request, contentType, parametersResult.entries().size(),
                parametersResult.droppedSynthesized(), parametersResult.bodyEnumerationSkipped());

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
     * Builds a request sub-document from raw bytes when Montoya accessors throw.
     *
     * <p>The fallback preserves export continuity for malformed Repeater requests by parsing the
     * raw request line and safely querying only the accessors that Burp still exposes. Missing
     * fields remain {@code null} instead of aborting the whole document.</p>
     */
    private static Map<String, Object> buildFallbackRequestDoc(HttpRequest request) {
        RawRequestSnapshot raw = RawRequestSnapshot.from(request);
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("method", raw.method());
        req.put("path", raw.path());
        req.put("path_without_query", nullToEmpty(raw.pathWithoutQuery()));
        req.put("query", nullToEmpty(raw.query()));
        req.put("file_extension", nullToEmpty(raw.fileExtension()));
        req.put("http_version", raw.httpVersion());

        burp.api.montoya.http.message.ContentType contentType = safeContentType(request);
        req.put("content_type", contentType == null ? null : contentType.toString());
        req.put("content_type_enum", contentType == null ? null : contentType.name());

        List<HttpHeader> requestHeaders = safeHeaders(request);
        String inferredContentType = inferRequestContentType(raw.bodyBytes(), requestHeaders);
        req.put("inferred_content_type", inferredContentType);
        req.put("headers", buildHeadersObject(requestHeaders));
        req.put("parameters", safeParameters(request, contentType, requestHeaders, inferredContentType));

        putBodyFields(
                req,
                raw.bodyBytes(),
                requestHeaders,
                mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                false,
                raw.bodyOffset());

        req.put("markers", safeMarkers(request));
        return req;
    }

    /**
     * Builds a response sub-document matching the traffic index response shape.
     *
     * <p>Body bytes are always stored as full base64 in {@code body.b64} for exact replay. When
     * the payload is classified as textual, {@code body.text} contains the full decoded text. For
     * {@link HttpResponseReceived}, response attributes such as {@code visible_text} are preserved
     * as returned by Montoya.</p>
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

    private static void putResponseBodyField(Map<String, Object> responseDoc, String field, Object value) {
        if (responseDoc == null || field == null) {
            return;
        }
        Map<String, Object> body = nestedStringKeyedMap(responseDoc, "body", LinkedHashMap::new);
        body.put(field, value);
    }

    private static void putResponseHeaderField(Map<String, Object> responseDoc, String field, Object value) {
        if (responseDoc == null || field == null) {
            return;
        }
        Map<String, Object> headers = nestedStringKeyedMap(responseDoc, "headers", () -> {
            Map<String, Object> fresh = new LinkedHashMap<>();
            fresh.put("full", List.of());
            return fresh;
        });
        headers.put(field, value);
    }

    /**
     * Returns the nested {@code Map<String, Object>} stored under {@code key} in {@code parent},
     * or initializes it with {@code initializer} and inserts it when absent or of the wrong type.
     *
     * <p>Single centralized suppression for response-document assembly: every nested map in the
     * response JSON is built by this class as {@code Map<String, Object>}, so the
     * {@code instanceof Map<?, ?>} guard plus this cast simply re-assert the generic parameters
     * that type erasure strips at runtime.</p>
     */
    @SuppressWarnings("unchecked") // Nested response-document maps are always built here as Map<String, Object>.
    private static Map<String, Object> nestedStringKeyedMap(
            Map<String, Object> parent,
            String key,
            Supplier<Map<String, Object>> initializer) {
        Object existing = parent.get(key);
        if (existing instanceof Map<?, ?>) {
            return (Map<String, Object>) existing;
        }
        Map<String, Object> fresh = initializer.get();
        parent.put(key, fresh);
        return fresh;
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

    /**
     * Decides whether synthesized {@code BODY}-typed parameters should be retained for this request.
     *
     * <p>Burp's {@code HttpRequest.parameters()} emits one {@code BODY} {@link ParsedHttpParameter}
     * per byte-run it finds in the request body regardless of Content-Type. For binary bodies
     * (protobuf, gzip, octet-stream, multipart, images, etc.) this produces tens or hundreds of
     * thousands of synthetic entries with non-printable names and empty values - a parser artifact,
     * not real HTTP parameters. Since raw body bytes remain in {@code request.body.b64}, dropping
     * these on binary bodies is fidelity-neutral and avoids blowing past the OpenSearch
     * {@code nested_objects.limit}.</p>
     *
     * <p>The gate is a short-circuit chain, strongest signal first:</p>
     * <ol>
     *   <li>Inferred {@value #INFERRED_CT_BINARY} body → drop BODY. Catches the Content-Type
     *       spoofing case (for example protobuf declared as {@code application/x-www-form-urlencoded})
     *       that earlier declared-only gating missed.</li>
     *   <li>Declared {@code URL_ENCODED} or {@code MULTIPART} → include BODY. Canonical form.</li>
     *   <li>Declared {@code JSON} / {@code XML} / {@code AMF} → drop BODY. These types do not
     *       legitimately emit {@link HttpParameterType#BODY} entries.</li>
     *   <li>Otherwise (absent / {@code NONE} / {@code UNKNOWN}) → fall back to the Content-Type
     *       header, dropping only when the header is explicitly binary. Preserves legacy behavior
     *       for headerless form posts.</li>
     * </ol>
     */
    static boolean shouldIncludeBodyParameters(
            burp.api.montoya.http.message.ContentType contentType,
            List<HttpHeader> headers,
            String inferredContentType) {
        if (INFERRED_CT_BINARY.equals(inferredContentType)) {
            return false;
        }
        String declaredName = contentType == null ? null : contentType.name();
        if ("URL_ENCODED".equals(declaredName) || "MULTIPART".equals(declaredName)) {
            return true;
        }
        if ("JSON".equals(declaredName) || "XML".equals(declaredName) || "AMF".equals(declaredName)) {
            return false;
        }
        String header = contentType == null ? null : contentType.toString();
        String primary = primaryMediaType(header, mediaTypeHints(declaredName));
        if (primary == null) {
            primary = mediaType(header, null);
        }
        if (primary == null && headers != null) {
            for (HttpHeader h : headers) {
                if (h != null && h.name() != null && "content-type".equalsIgnoreCase(h.name())) {
                    primary = mediaType(h.value(), null);
                    if (primary != null) break;
                }
            }
        }
        return !isExplicitlyBinaryMediaType(primary);
    }

    /**
     * Computes the {@code request.inferred_content_type} verdict from body bytes alone.
     *
     * <p>Mirrors the role of Burp's {@code response.inferredMimeType()} on the request side,
     * where Montoya does not expose an equivalent accessor. Preserves declared
     * {@code content_type} verbatim; consumers can compare the two to flag Content-Type
     * spoofing. Also feeds {@link #shouldIncludeBodyParameters} as the primary override
     * signal for binary bodies.</p>
     *
     * <p>Sniff ordering (first match wins):</p>
     * <ol>
     *   <li>Null or empty body → {@value #INFERRED_CT_EMPTY}.</li>
     *   <li>Any NUL byte in the first {@value #TEXT_SNIFF_BYTES} scanned → {@value #INFERRED_CT_BINARY}.</li>
     *   <li>Bytes fail UTF-8 / charset-hint decode, or post-decode control-character ratio is above
     *       {@link #MAX_CONTROL_CHAR_RATIO} → {@value #INFERRED_CT_BINARY}.</li>
     *   <li>First non-whitespace character classifies textual content:
     *       <ul>
     *         <li>{@code '{'} / {@code '['} → {@value #INFERRED_CT_JSON}.</li>
     *         <li>{@code '<'} → {@value #INFERRED_CT_XML}.</li>
     *         <li>{@code "--"} prefix → {@value #INFERRED_CT_MULTIPART}.</li>
     *         <li>Any other printable content → {@value #INFERRED_CT_TEXT}.</li>
     *       </ul>
     *   </li>
     *   <li>Purely whitespace text → {@value #INFERRED_CT_TEXT}.</li>
     * </ol>
     */
    static String inferRequestContentType(byte[] bodyBytes, List<HttpHeader> headers) {
        if (bodyBytes == null || bodyBytes.length == 0) {
            return INFERRED_CT_EMPTY;
        }
        int scanLen = Math.min(bodyBytes.length, TEXT_SNIFF_BYTES);
        byte[] sample;
        if (scanLen == bodyBytes.length) {
            sample = bodyBytes;
        } else {
            sample = new byte[scanLen];
            System.arraycopy(bodyBytes, 0, sample, 0, scanLen);
        }
        if (containsNul(sample)) {
            return INFERRED_CT_BINARY;
        }
        Charset charset = charsetFromContentType(headerValue(headers, "Content-Type"));
        String decoded = decodeTextWithFallback(sample, charset);
        if (decoded == null || !hasLowControlCharacterRatio(decoded)) {
            return INFERRED_CT_BINARY;
        }
        int i = 0;
        int n = decoded.length();
        while (i < n && Character.isWhitespace(decoded.charAt(i))) {
            i++;
        }
        if (i >= n) {
            return INFERRED_CT_TEXT;
        }
        char first = decoded.charAt(i);
        if (first == '{' || first == '[') {
            return INFERRED_CT_JSON;
        }
        if (first == '<') {
            return INFERRED_CT_XML;
        }
        if (first == '-' && i + 1 < n && decoded.charAt(i + 1) == '-') {
            return INFERRED_CT_MULTIPART;
        }
        return INFERRED_CT_TEXT;
    }

    /**
     * Result of converting Burp's request parameters into the doc representation.
     *
     * <p>Carries the retained entries, the count of synthesized {@code BODY}-typed entries
     * filtered out because the body was binary, and a flag indicating whether the typed-accessor
     * fast path was used (i.e. Burp's unfiltered {@code parameters()} call was skipped to avoid
     * materializing millions of synthetic BODY entries on Content-Type-spoofed binary bodies).
     * The {@code droppedSynthesized} count feeds the {@code ExportStats} telemetry counters; the
     * {@code bodyEnumerationSkipped} flag drives the {@code Skipped BODY Enumeration} counter.</p>
     */
    record ParametersResult(List<Map<String, Object>> entries, int droppedSynthesized, boolean bodyEnumerationSkipped) {
        static final ParametersResult EMPTY = new ParametersResult(List.of(), 0, false);
    }

    /** Non-BODY parameter types enumerated by the typed-accessor fast path. */
    private static final HttpParameterType[] NON_BODY_PARAMETER_TYPES = new HttpParameterType[] {
            HttpParameterType.URL,
            HttpParameterType.COOKIE,
            HttpParameterType.JSON,
            HttpParameterType.XML,
            HttpParameterType.XML_ATTRIBUTE,
            HttpParameterType.MULTIPART_ATTRIBUTE
    };

    /**
     * Collects request parameters for the doc representation, choosing between Burp's unfiltered
     * {@link HttpRequest#parameters()} and the typed-by-type fast path based on whether BODY
     * entries are wanted.
     *
     * <p>When {@code includeBody} is {@code false} the typed-accessor fast path enumerates only
     * non-BODY parameter types. This is the heap-safety primary defence against Content-Type
     * spoofing, where a binary request body declared as {@code application/x-www-form-urlencoded}
     * would otherwise cause Burp's parser to synthesize tens of millions of fake BODY entries
     * before our hard cap can drop them. By querying typed accessors directly we never trigger
     * the synthetic enumeration in the first place and {@code droppedSynthesized} is reported as
     * {@code 0} for that branch (with the {@code Skipped BODY Enumeration} counter incrementing
     * instead).</p>
     *
     * <p>When {@code includeBody} is {@code true} the unfiltered {@code parameters()} call is
     * used (legitimate form-encoded bodies need every type) and dropping/capping is delegated to
     * the existing {@link #parametersToList(List, boolean)} routine.</p>
     */
    static ParametersResult collectParameters(HttpRequest request, boolean includeBody) {
        if (request == null) {
            return ParametersResult.EMPTY;
        }
        if (includeBody) {
            ParametersResult fullScan = parametersToList(request.parameters(), true);
            return new ParametersResult(fullScan.entries(), fullScan.droppedSynthesized(), false);
        }
        List<ParsedHttpParameter> merged = new ArrayList<>();
        for (HttpParameterType type : NON_BODY_PARAMETER_TYPES) {
            try {
                if (!request.hasParameters(type)) {
                    continue;
                }
                List<ParsedHttpParameter> typed = request.parameters(type);
                if (typed == null || typed.isEmpty()) {
                    continue;
                }
                merged.addAll(typed);
                if (merged.size() >= PARAMETERS_HARD_CAP) {
                    break;
                }
            } catch (RuntimeException ignored) {
                // Per-type accessor may throw on malformed inputs; skip that type and keep going
                // so a single bad accessor does not lose the whole parameter list.
            }
        }
        ParametersResult capped = parametersToList(merged, true);
        return new ParametersResult(capped.entries(), 0, true);
    }

    /**
     * Converts {@code request.parameters()} to the exported list form, optionally filtering
     * synthesized {@code BODY}-typed entries when the body is not form-encoded, and enforcing
     * the {@link #PARAMETERS_HARD_CAP} safety ceiling against Content-Type spoofing.
     *
     * <p>When {@code includeBody} is {@code false}, {@link HttpParameterType#BODY} entries are
     * skipped and counted; all other types (URL, COOKIE, XML, JSON, MULTIPART_ATTRIBUTE, and
     * {@code null}/unknown) are preserved. When {@code includeBody} is {@code true}, BODY
     * entries are retained up to the hard cap.</p>
     *
     * <p>The hard cap is applied in two stages. First, if {@code includeBody} is {@code true}
     * and the total parameter count exceeds {@link #PARAMETERS_HARD_CAP} <em>and</em> BODY
     * entries alone exceed the cap, all BODY entries are dropped (Burp's parser is treating a
     * non-form body as form-encoded). Second, if the remaining list still exceeds the cap it is
     * truncated, so no single request can emit more than {@link #PARAMETERS_HARD_CAP} nested
     * parameter documents. Dropped entries at both stages are counted in the returned result.</p>
     */
    static ParametersResult parametersToList(List<ParsedHttpParameter> parameters, boolean includeBody) {
        if (parameters == null || parameters.isEmpty()) {
            return ParametersResult.EMPTY;
        }
        boolean effectiveIncludeBody = includeBody;
        if (effectiveIncludeBody && parameters.size() > PARAMETERS_HARD_CAP) {
            int bodyCount = 0;
            for (ParsedHttpParameter p : parameters) {
                if (p != null && p.type() == HttpParameterType.BODY) {
                    bodyCount++;
                    if (bodyCount > PARAMETERS_HARD_CAP) {
                        effectiveIncludeBody = false;
                        break;
                    }
                }
            }
        }
        List<Map<String, Object>> out = new ArrayList<>(Math.min(parameters.size(), PARAMETERS_HARD_CAP));
        int dropped = 0;
        for (ParsedHttpParameter p : parameters) {
            HttpParameterType type = p.type();
            if (!effectiveIncludeBody && type == HttpParameterType.BODY) {
                dropped++;
                continue;
            }
            if (out.size() >= PARAMETERS_HARD_CAP) {
                dropped++;
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>(3);
            entry.put("name", p.name());
            entry.put("value", p.value());
            entry.put("type", type == null ? null : type.name());
            out.add(entry);
        }
        return new ParametersResult(out, dropped, false);
    }

    /**
     * Records parameter-cardinality telemetry for one request and, when a threshold is crossed,
     * emits a single log line classified by the kind of cardinality observed.
     *
     * <p>Split-level logging so users are not confused by WARN output on the common case:</p>
     * <ul>
     *   <li><b>Real anomaly</b> ({@code retained >= PARAMETERS_WARN_THRESHOLD}): legitimate
     *       request with thousands of real parameters. Emits {@code WARN} on the panel so
     *       operators notice. Message tag: {@code [ParameterCardinality][retained]}.</li>
     *   <li><b>Routine filter activity</b> ({@code droppedSynthesized >= PARAMETERS_WARN_THRESHOLD}
     *       while {@code retained} stays below threshold): a Content-Type mismatch caused Burp's
     *       parameter parser to fabricate synthetic {@code BODY} entries from a binary request
     *       body whose declared Content-Type (typically {@code URL_ENCODED}) did not match the
     *       actual bytes, and our synthetic-BODY filter dropped them. Expected and common on
     *       protobuf, gRPC, or other binary request bodies mis-declared as form-encoded, so only
     *       {@code DEBUG} is emitted. Message tag: {@code [ParameterCardinality][synthesized_dropped]}.</li>
     * </ul>
     *
     * <p>Both the {@code Synthesized Body Params Dropped} counter (on every non-zero drop) and
     * the {@code Docs Over Param Threshold} counter (on every threshold crossing, regardless of
     * branch) always update in {@link ai.attackframework.tools.burp.utils.ExportStats} so
     * dashboards stay complete independent of log level.</p>
     */
    /** Package-private for direct testing of the threshold branches. */
    static void recordParameterTelemetry(
            HttpRequest request,
            burp.api.montoya.http.message.ContentType contentType,
            int retained,
            int droppedSynthesized,
            boolean bodyEnumerationSkipped) {
        if (droppedSynthesized > 0) {
            ai.attackframework.tools.burp.utils.ExportStats.recordSynthesizedBodyParamsDropped(droppedSynthesized);
        }
        if (bodyEnumerationSkipped) {
            ai.attackframework.tools.burp.utils.ExportStats.recordSkippedBodyParameterEnumeration();
        }
        boolean retainedHigh = retained >= PARAMETERS_WARN_THRESHOLD;
        boolean droppedHigh = droppedSynthesized >= PARAMETERS_WARN_THRESHOLD;
        if (!retainedHigh && !droppedHigh && !bodyEnumerationSkipped) {
            return;
        }
        if (retainedHigh || droppedHigh) {
            ai.attackframework.tools.burp.utils.ExportStats.recordDocsOverParamsThreshold();
        }
        String ct = contentType == null ? "unknown" : contentType.toString();
        String commonFields = formatCommonFields(
                safeMethod(request),
                safeTruncatedUrl(request),
                ct,
                retained,
                droppedSynthesized);
        if (retainedHigh) {
            Logger.logWarnPanelOnly("[ParameterCardinality][retained] High retained parameter count; "
                    + "likely a legitimate request with unusual cardinality - review: " + commonFields);
        } else if (droppedHigh) {
            Logger.logDebug("[ParameterCardinality][synthesized_dropped] Content-Type mismatch "
                    + "caused Burp's parameters() API to mis-infer "
                    + droppedSynthesized
                    + " synthetic BODY parameters: the request declared a form-encoded "
                    + "Content-Type (" + ct + ") but carried a binary body, so Burp scanned the "
                    + "raw bytes as if form-encoded and fabricated entries. All dropped. "
                    + "Expected on binary request bodies such as protobuf/gRPC: " + commonFields);
        } else {
            Logger.logDebug("[ParameterCardinality][skipped_body_enumeration] Skipped synthetic BODY "
                    + "enumeration on a non-form / binary body to keep heap bounded; only non-BODY "
                    + "parameter types were collected: " + commonFields);
        }
    }

    private static String safeMethod(HttpRequest request) {
        try {
            if (request != null && request.method() != null) {
                return request.method();
            }
        } catch (RuntimeException ignored) { /* fall through to "unknown" */ }
        return "unknown";
    }

    private static String safeTruncatedUrl(HttpRequest request) {
        String url = normalizeBlank(safeRequestUrl(request, "ParameterCardinality"));
        if (url == null) {
            return "unknown";
        }
        if (url.length() > PARAMETERS_WARN_URL_MAX_LEN) {
            return url.substring(0, PARAMETERS_WARN_URL_MAX_LEN) + "...";
        }
        return url;
    }

    private static String formatCommonFields(
            String method, String url, String contentType, int retained, int droppedSynthesized) {
        return "method=" + method
                + " url=" + url
                + " content_type=" + contentType
                + " retained=" + retained
                + " dropped_synthesized=" + droppedSynthesized;
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
            boolean includeBody = shouldIncludeBodyParameters(contentType, headers, inferredContentType);
            ParametersResult result = collectParameters(request, includeBody);
            recordParameterTelemetry(request, contentType, result.entries().size(),
                    result.droppedSynthesized(), result.bodyEnumerationSkipped());
            return result.entries();
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    private static List<Map<String, Object>> safeMarkers(HttpRequest request) {
        if (request == null) {
            return List.of();
        }
        try {
            return markersToList(request.markers());
        } catch (RuntimeException ignored) {
            return List.of();
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
            return request == null ? null : normalizeBlank(request.url());
        } catch (RuntimeException e) {
            String prefix = normalizeBlank(logPrefix);
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

    private static String stringValue(Object value) {
        return value == null ? null : String.valueOf(value);
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
            String method = normalizeBlank(parts.length > 0 ? parts[0] : null);
            String path = normalizeBlank(parts.length > 1 ? parts[1] : null);
            String httpVersion = normalizeBlank(parts.length > 2 ? parts[2] : null);
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
     * - body.text: full decoded text when content is dynamically classified as searchable text
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

    private static String normalizeBlank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
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
