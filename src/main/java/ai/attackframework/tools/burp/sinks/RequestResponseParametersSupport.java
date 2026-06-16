package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.nio.charset.Charset;

import ai.attackframework.tools.burp.utils.Logger;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.ContentType;

/** Request parameter collection, inference, and telemetry. */
final class RequestResponseParametersSupport {

    private RequestResponseParametersSupport() {}

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
    static final int PARAMETERS_WARN_URL_MAX_LEN = 200;
    static String statusCodeClassName(short statusCode) {
        for (StatusCodeClass c : StatusCodeClass.values()) {
            if (c.contains(statusCode)) {
                return c.name();
            }
        }
        return null;
    }
    static boolean shouldIncludeBodyParameters(
            ContentType contentType,
            List<HttpHeader> headers,
            String inferredContentType) {
        if (HttpMessageDocSupport.INFERRED_CT_BINARY.equals(inferredContentType)) {
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
        String primary = HttpMessageDocSupport.primaryMediaType(header, HttpMessageDocSupport.mediaTypeHints(declaredName));
        if (primary == null) {
            primary = HttpMessageDocSupport.mediaType(header, null);
        }
        if (primary == null && headers != null) {
            for (HttpHeader h : headers) {
                if (h != null && h.name() != null && "content-type".equalsIgnoreCase(h.name())) {
                    primary = HttpMessageDocSupport.mediaType(h.value(), null);
                    if (primary != null) break;
                }
            }
        }
        return !HttpMessageDocSupport.isExplicitlyBinaryMediaType(primary);
    }

    /**
     * Computes the traffic {@code request.header.content-type_inferred} verdict from body bytes alone.
     *
     * <p>Mirrors the role of Burp's {@code response.inferredMimeType()} on the request side,
     * where Montoya does not expose an equivalent accessor. Preserves declared
     * {@code content_type} verbatim; consumers can compare the two to flag Content-Type
     * spoofing. Also feeds {@link #shouldIncludeBodyParameters} as the primary override
     * signal for binary bodies.</p>
     *
     * <p>Sniff ordering (first match wins):</p>
     * <ol>
     *   <li>Null or empty body → {@value #HttpMessageDocSupport.INFERRED_CT_EMPTY}.</li>
     *   <li>Any NUL byte in the first {@value #HttpMessageDocSupport.TEXT_SNIFF_BYTES} scanned → {@value #HttpMessageDocSupport.INFERRED_CT_BINARY}.</li>
     *   <li>Bytes fail UTF-8 / charset-hint decode, or post-decode control-character ratio is above
     *       {@link HttpMessageDocSupport#MAX_CONTROL_CHAR_RATIO} → {@value #HttpMessageDocSupport.INFERRED_CT_BINARY}.</li>
     *   <li>First non-whitespace character classifies textual content:
     *       <ul>
     *         <li>{@code '{'} / {@code '['} → {@value #HttpMessageDocSupport.INFERRED_CT_JSON}.</li>
     *         <li>{@code '<'} → {@value #HttpMessageDocSupport.INFERRED_CT_XML}.</li>
     *         <li>{@code "--"} prefix → {@value #HttpMessageDocSupport.INFERRED_CT_MULTIPART}.</li>
     *         <li>Any other printable content → {@value #HttpMessageDocSupport.INFERRED_CT_TEXT}.</li>
     *       </ul>
     *   </li>
     *   <li>Purely whitespace text → {@value #HttpMessageDocSupport.INFERRED_CT_TEXT}.</li>
     * </ol>
     */
    static String inferRequestContentType(byte[] bodyBytes, List<HttpHeader> headers) {
        if (bodyBytes == null || bodyBytes.length == 0) {
            return HttpMessageDocSupport.INFERRED_CT_EMPTY;
        }
        int scanLen = Math.min(bodyBytes.length, HttpMessageDocSupport.TEXT_SNIFF_BYTES);
        byte[] sample;
        if (scanLen == bodyBytes.length) {
            sample = bodyBytes;
        } else {
            sample = new byte[scanLen];
            System.arraycopy(bodyBytes, 0, sample, 0, scanLen);
        }
        if (HttpMessageDocSupport.containsNul(sample)) {
            return HttpMessageDocSupport.INFERRED_CT_BINARY;
        }
        Charset charset = HttpMessageDocSupport.charsetFromContentType(HttpMessageDocSupport.headerValue(headers, "Content-Type"));
        String decoded = HttpMessageDocSupport.decodeTextWithFallback(sample, charset);
        if (decoded == null || !HttpMessageDocSupport.hasLowControlCharacterRatio(decoded)) {
            return HttpMessageDocSupport.INFERRED_CT_BINARY;
        }
        int i = 0;
        int n = decoded.length();
        while (i < n && Character.isWhitespace(decoded.charAt(i))) {
            i++;
        }
        if (i >= n) {
            return HttpMessageDocSupport.INFERRED_CT_TEXT;
        }
        char first = decoded.charAt(i);
        if (first == '{' || first == '[') {
            return HttpMessageDocSupport.INFERRED_CT_JSON;
        }
        if (first == '<') {
            return HttpMessageDocSupport.INFERRED_CT_XML;
        }
        if (first == '-' && i + 1 < n && decoded.charAt(i + 1) == '-') {
            return HttpMessageDocSupport.INFERRED_CT_MULTIPART;
        }
        return HttpMessageDocSupport.INFERRED_CT_TEXT;
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
    static final HttpParameterType[] NON_BODY_PARAMETER_TYPES = new HttpParameterType[] {
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

    static List<Map<String, Object>> sitemapUrlParameters(HttpRequest request) {
        if (request == null) {
            return List.of();
        }
        List<ParsedHttpParameter> parameters = request.parameters(HttpParameterType.URL);
        return parametersToList(parameters, true).entries();
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
     * <p>Routine body-enumeration skips (non-form / binary bodies) update
     * {@link ai.attackframework.tools.burp.utils.ExportStats} only; they are not logged. The
     * {@code Synthesized Body Params Dropped} and {@code Docs Over Param Threshold} counters
     * also update in {@link ai.attackframework.tools.burp.utils.ExportStats} independent of log
     * level.</p>
     */
    /** Package-private for direct testing of the threshold branches. */
    static void recordParameterTelemetry(
            HttpRequest request,
            ContentType contentType,
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
        if (!retainedHigh && !droppedHigh) {
            return;
        }
        ai.attackframework.tools.burp.utils.ExportStats.recordDocsOverParamsThreshold();
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
        } else {
            Logger.logDebug("[ParameterCardinality][synthesized_dropped] Content-Type mismatch "
                    + "caused Burp's parameters() API to mis-infer "
                    + droppedSynthesized
                    + " synthetic BODY parameters: the request declared a form-encoded "
                    + "Content-Type (" + ct + ") but carried a binary body, so Burp scanned the "
                    + "raw bytes as if form-encoded and fabricated entries. All dropped. "
                    + "Expected on binary request bodies such as protobuf/gRPC: " + commonFields);
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
        String url = HttpMessageDocSupport.normalizeBlank(
                RequestResponseDocBuilder.safeRequestUrl(request, "ParameterCardinality"));
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
}
