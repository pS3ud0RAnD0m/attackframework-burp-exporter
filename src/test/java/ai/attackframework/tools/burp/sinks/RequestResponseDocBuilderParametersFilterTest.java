package ai.attackframework.tools.burp.sinks;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Covers the synthesized-BODY-parameter filter and the high-cardinality WARN
 * threshold. Tests target the package-private helpers directly so they exercise the same
 * code paths the production builder uses without needing the full request-doc wiring.
 */
class RequestResponseDocBuilderParametersFilterTest {

    private final List<LoggedEvent> events = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> events.add(new LoggedEvent(level, message));

    @BeforeEach
    void registerLogListener() {
        ExportStats.resetForTests();
        Logger.resetState();
        Logger.registerListener(listener);
    }

    @AfterEach
    void unregisterLogListener() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        events.clear();
    }

    @Test
    void parametersToList_includeBodyTrue_keepsEverything() {
        List<ParsedHttpParameter> input = List.of(
                param("u", "1", HttpParameterType.URL),
                param("c", "2", HttpParameterType.COOKIE),
                param("b1", "", HttpParameterType.BODY),
                param("b2", "", HttpParameterType.BODY),
                param("null-type", "x", null));

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.parametersToList(input, true);

        assertThat(result.entries()).hasSize(5);
        assertThat(result.droppedSynthesized()).isZero();
    }

    @Test
    void parametersToList_includeBodyFalse_dropsBodyOnly() {
        List<ParsedHttpParameter> input = List.of(
                param("u", "1", HttpParameterType.URL),
                param("c", "2", HttpParameterType.COOKIE),
                param("b1", "", HttpParameterType.BODY),
                param("b2", "", HttpParameterType.BODY),
                param("null-type", "x", null));

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.parametersToList(input, false);

        assertThat(result.entries())
                .extracting(e -> e.get("type"))
                .containsExactly("URL", "COOKIE", null);
        assertThat(result.droppedSynthesized()).isEqualTo(2);
    }

    @Test
    void parametersToList_emptyOrNullInput_returnsEmptyResult() {
        assertThat(RequestResponseDocBuilder.parametersToList(null, false).entries()).isEmpty();
        assertThat(RequestResponseDocBuilder.parametersToList(List.of(), true).entries()).isEmpty();
    }

    @Test
    void parametersToList_hardCap_dropsAllBodyWhenBodyCountExceedsCap() {
        int cap = RequestResponseParametersSupport.PARAMETERS_HARD_CAP;
        List<ParsedHttpParameter> input = new java.util.ArrayList<>(cap + 50);
        input.add(param("u", "1", HttpParameterType.URL));
        input.add(param("c", "2", HttpParameterType.COOKIE));
        for (int i = 0; i < cap + 10; i++) {
            input.add(param("b" + i, "", HttpParameterType.BODY));
        }

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.parametersToList(input, true);

        assertThat(result.entries())
                .extracting(e -> e.get("type"))
                .containsExactly("URL", "COOKIE");
        assertThat(result.droppedSynthesized()).isEqualTo(cap + 10);
    }

    @Test
    void parametersToList_hardCap_truncatesWhenNonBodyExceedsCap() {
        int cap = RequestResponseParametersSupport.PARAMETERS_HARD_CAP;
        List<ParsedHttpParameter> input = new java.util.ArrayList<>(cap + 5);
        for (int i = 0; i < cap + 5; i++) {
            input.add(param("u" + i, "v", HttpParameterType.URL));
        }

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.parametersToList(input, true);

        assertThat(result.entries()).hasSize(cap);
        assertThat(result.droppedSynthesized()).isEqualTo(5);
    }

    @Test
    void parametersToList_hardCap_keepsBodyWhenBodyCountUnderCap() {
        int cap = RequestResponseParametersSupport.PARAMETERS_HARD_CAP;
        List<ParsedHttpParameter> input = new java.util.ArrayList<>(cap + 1);
        for (int i = 0; i < cap - 1; i++) {
            input.add(param("u" + i, "v", HttpParameterType.URL));
        }
        input.add(param("b1", "", HttpParameterType.BODY));
        input.add(param("b2", "", HttpParameterType.BODY));

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.parametersToList(input, true);

        assertThat(result.entries()).hasSize(cap);
        assertThat(result.droppedSynthesized()).isEqualTo(1);
    }

    @Test
    void shouldIncludeBodyParameters_formEnumValues_returnTrue() {
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.URL_ENCODED, List.of(), HttpMessageDocSupport.INFERRED_CT_TEXT)).isTrue();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.MULTIPART, List.of(), HttpMessageDocSupport.INFERRED_CT_MULTIPART)).isTrue();
    }

    @Test
    void shouldIncludeBodyParameters_declaredFormButInferredBinary_returnsFalse() {
        // The Google federatedcompute case: Content-Type: application/x-www-form-urlencoded on a
        // raw protobuf body. Declared says form, inference sees binary, gate must drop BODY.
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.URL_ENCODED, List.of(), HttpMessageDocSupport.INFERRED_CT_BINARY)).isFalse();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.MULTIPART, List.of(), HttpMessageDocSupport.INFERRED_CT_BINARY)).isFalse();
    }

    @Test
    void shouldIncludeBodyParameters_declaredNonFormTextual_returnsFalse() {
        // JSON / XML / AMF should not legitimately emit BODY params; drop regardless of inference.
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.JSON, List.of(), HttpMessageDocSupport.INFERRED_CT_JSON)).isFalse();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.XML, List.of(), HttpMessageDocSupport.INFERRED_CT_XML)).isFalse();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.AMF, List.of(), HttpMessageDocSupport.INFERRED_CT_TEXT)).isFalse();
    }

    @Test
    void shouldIncludeBodyParameters_noneOrUnknownEnum_withoutHeader_returnsTrue() {
        // Absent/unknown declared + no header + non-binary body preserves legacy headerless-form behavior.
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.NONE, List.of(), HttpMessageDocSupport.INFERRED_CT_TEXT)).isTrue();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.UNKNOWN, List.of(), HttpMessageDocSupport.INFERRED_CT_TEXT)).isTrue();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                null, null, HttpMessageDocSupport.INFERRED_CT_EMPTY)).isTrue();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                null, List.of(), HttpMessageDocSupport.INFERRED_CT_TEXT)).isTrue();
    }

    @Test
    void shouldIncludeBodyParameters_headerFallback_binaryReturnsFalse() {
        assertBinaryHeaderFiltered("application/protobuf");
        assertBinaryHeaderFiltered("application/x-protobuf");
        assertBinaryHeaderFiltered("application/grpc");
        assertBinaryHeaderFiltered("application/octet-stream");
        assertBinaryHeaderFiltered("image/png");
        assertBinaryHeaderFiltered("application/zip");
        assertBinaryHeaderFiltered("application/gzip");
        assertBinaryHeaderFiltered("multipart/form-data; boundary=abc");
    }

    @Test
    void shouldIncludeBodyParameters_headerFallback_textualReturnsTrue() {
        assertTextualHeaderKept("application/x-www-form-urlencoded");
        assertTextualHeaderKept("text/plain");
        assertTextualHeaderKept("text/html; charset=utf-8");
    }

    @Test
    void inferRequestContentType_emptyOrNull_returnsEmpty() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(null, null))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_EMPTY);
        assertThat(RequestResponseDocBuilder.inferRequestContentType(new byte[0], List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_EMPTY);
    }

    @Test
    void inferRequestContentType_nulBytes_returnsBinary() {
        byte[] bytes = new byte[]{0x01, 0x02, 0x00, 0x03, 0x04};
        assertThat(RequestResponseDocBuilder.inferRequestContentType(bytes, List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_BINARY);
    }

    @Test
    void inferRequestContentType_highControlCharRatio_returnsBinary() {
        byte[] bytes = new byte[64];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = 0x01;
        }
        assertThat(RequestResponseDocBuilder.inferRequestContentType(bytes, List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_BINARY);
    }

    @Test
    void inferRequestContentType_jsonObject_returnsJson() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(
                "  {\"a\":1}".getBytes(java.nio.charset.StandardCharsets.UTF_8), List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_JSON);
    }

    @Test
    void inferRequestContentType_jsonArray_returnsJson() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(
                "[1,2,3]".getBytes(java.nio.charset.StandardCharsets.UTF_8), List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_JSON);
    }

    @Test
    void inferRequestContentType_xml_returnsXml() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(
                "<?xml version=\"1.0\"?><root/>".getBytes(java.nio.charset.StandardCharsets.UTF_8), List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_XML);
    }

    @Test
    void inferRequestContentType_multipart_returnsMultipart() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(
                "--boundary123\r\nContent-Disposition: form-data".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_MULTIPART);
    }

    @Test
    void inferRequestContentType_plainText_returnsText() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(
                "name=value&other=thing".getBytes(java.nio.charset.StandardCharsets.UTF_8), List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_TEXT);
    }

    @Test
    void recordParameterTelemetry_belowThreshold_doesNotEmitWarn_butDropsStillCounted() throws Exception {
        HttpRequest request = mockRequest("POST", "https://example.test/api");

        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterTelemetry(
                        request, ContentType.JSON, 10, 4_999, false));

        assertThat(events).noneMatch(e -> e.message().contains("[ParameterCardinality]"));
        assertThat(ExportStats.getSynthesizedBodyParamsDropped()).isEqualTo(4_999);
        assertThat(ExportStats.getDocsOverParamsThreshold()).isZero();
    }

    @Test
    void recordParameterTelemetry_droppedAtThreshold_emitsDebugExplainingCause() throws Exception {
        HttpRequest request = mockRequest("POST", "https://example.test/upload");

        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterTelemetry(
                        request, ContentType.URL_ENCODED,
                        /* retained */ 2, /* dropped */ RequestResponseParametersSupport.PARAMETERS_WARN_THRESHOLD,
                        /* bodyEnumerationSkipped */ false));

        assertThat(events).anySatisfy(e -> {
            assertThat(e.level()).isEqualToIgnoringCase("debug");
            assertThat(e.message())
                    .contains("[ParameterCardinality][synthesized_dropped]")
                    .contains("Content-Type mismatch")
                    .contains("mis-infer")
                    .contains("binary body")
                    .contains("All dropped")
                    .contains("protobuf/gRPC")
                    .contains("method=POST")
                    .contains("url=https://example.test/upload")
                    .contains("content_type=URL_ENCODED")
                    .contains("retained=2")
                    .contains("dropped_synthesized=" + RequestResponseParametersSupport.PARAMETERS_WARN_THRESHOLD);
        });
        assertThat(events).noneMatch(e -> "warn".equalsIgnoreCase(e.level())
                && e.message().contains("[ParameterCardinality]"));
        assertThat(ExportStats.getSynthesizedBodyParamsDropped())
                .isEqualTo(RequestResponseParametersSupport.PARAMETERS_WARN_THRESHOLD);
        assertThat(ExportStats.getDocsOverParamsThreshold()).isEqualTo(1);
    }

    @Test
    void recordParameterTelemetry_retainedAtThreshold_emitsWarnTaggedRetained() throws Exception {
        HttpRequest request = mockRequest("GET", "https://example.test/search");

        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterTelemetry(
                        request, ContentType.JSON,
                        /* retained */ RequestResponseParametersSupport.PARAMETERS_WARN_THRESHOLD, /* dropped */ 0,
                        /* bodyEnumerationSkipped */ false));

        assertThat(events).anySatisfy(e -> {
            assertThat(e.level()).isEqualToIgnoringCase("warn");
            assertThat(e.message())
                    .contains("[ParameterCardinality][retained]")
                    .contains("retained=" + RequestResponseParametersSupport.PARAMETERS_WARN_THRESHOLD);
        });
        assertThat(ExportStats.getDocsOverParamsThreshold()).isEqualTo(1);
        assertThat(ExportStats.getSynthesizedBodyParamsDropped()).isZero();
    }

    @Test
    void recordParameterTelemetry_bothHigh_prefersRetainedWarnOverDroppedDebug() throws Exception {
        HttpRequest request = mockRequest("POST", "https://example.test/both");

        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterTelemetry(
                        request, ContentType.MULTIPART,
                        /* retained */ RequestResponseParametersSupport.PARAMETERS_WARN_THRESHOLD,
                        /* dropped */ RequestResponseParametersSupport.PARAMETERS_WARN_THRESHOLD,
                        /* bodyEnumerationSkipped */ false));

        assertThat(events).anySatisfy(e -> {
            assertThat(e.level()).isEqualToIgnoringCase("warn");
            assertThat(e.message()).contains("[ParameterCardinality][retained]");
        });
        assertThat(events).noneMatch(e -> e.message().contains("[ParameterCardinality][synthesized_dropped]"));
        assertThat(ExportStats.getDocsOverParamsThreshold()).isEqualTo(1);
    }

    @Test
    void recordParameterTelemetry_longUrl_isTruncated() throws Exception {
        String longUrl = "https://example.test/" + "a".repeat(400);
        HttpRequest request = mockRequest("POST", longUrl);

        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterTelemetry(
                        request, ContentType.UNKNOWN,
                        0, RequestResponseParametersSupport.PARAMETERS_WARN_THRESHOLD, false));

        assertThat(events).anySatisfy(e -> {
            assertThat(e.message()).contains("[ParameterCardinality][synthesized_dropped]");
            assertThat(e.message()).contains("...");
            assertThat(e.message()).doesNotContain(longUrl);
        });
    }

    @Test
    void recordParameterTelemetry_nullRequest_doesNotThrow_andStillLogs() throws Exception {
        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterTelemetry(
                        null, ContentType.NONE, 0, RequestResponseParametersSupport.PARAMETERS_WARN_THRESHOLD, false));

        assertThat(events).anySatisfy(e -> assertThat(e.message())
                .contains("[ParameterCardinality][synthesized_dropped]")
                .contains("method=unknown")
                .contains("url=unknown"));
    }

    private static void assertBinaryHeaderFiltered(String contentTypeHeader) {
        List<HttpHeader> headers = List.of(header("Content-Type", contentTypeHeader));
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                null, headers, HttpMessageDocSupport.INFERRED_CT_TEXT))
                .as("header '%s' should classify body as binary", contentTypeHeader)
                .isFalse();
    }

    private static void assertTextualHeaderKept(String contentTypeHeader) {
        List<HttpHeader> headers = List.of(header("Content-Type", contentTypeHeader));
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                null, headers, HttpMessageDocSupport.INFERRED_CT_TEXT))
                .as("header '%s' should classify body as textual", contentTypeHeader)
                .isTrue();
    }

    @Test
    void collectParameters_includeBodyFalse_usesTypedAccessors_andNeverCallsUnfilteredParameters() {
        // Build mocks BEFORE nesting them inside when(...).thenReturn(...) — Mockito otherwise
        // raises UnfinishedStubbingException when a stubbed method is created inside another
        // stubbing call.
        ParsedHttpParameter url1 = param("q", "1", HttpParameterType.URL);
        ParsedHttpParameter url2 = param("page", "2", HttpParameterType.URL);
        ParsedHttpParameter cookie = param("session", "abc", HttpParameterType.COOKIE);
        List<ParsedHttpParameter> urlParams = List.of(url1, url2);
        List<ParsedHttpParameter> cookieParams = List.of(cookie);
        HttpRequest request = mock(HttpRequest.class);
        when(request.hasParameters(HttpParameterType.URL)).thenReturn(true);
        when(request.parameters(HttpParameterType.URL)).thenReturn(urlParams);
        when(request.hasParameters(HttpParameterType.COOKIE)).thenReturn(true);
        when(request.parameters(HttpParameterType.COOKIE)).thenReturn(cookieParams);
        when(request.hasParameters(HttpParameterType.JSON)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML_ATTRIBUTE)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.MULTIPART_ATTRIBUTE)).thenReturn(false);

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.collectParameters(request, false);

        assertThat(result.entries()).hasSize(3);
        assertThat(result.droppedSynthesized()).isZero();
        assertThat(result.bodyEnumerationSkipped()).isTrue();
        verify(request, never()).parameters();
        verify(request, never()).parameters(HttpParameterType.BODY);
    }

    @Test
    void collectParameters_includeBodyTrue_callsUnfilteredParameters_andDoesNotMarkSkipped() {
        ParsedHttpParameter urlParam = param("u", "1", HttpParameterType.URL);
        ParsedHttpParameter bodyParam = param("b1", "x", HttpParameterType.BODY);
        List<ParsedHttpParameter> all = List.of(urlParam, bodyParam);
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(all);

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.collectParameters(request, true);

        assertThat(result.entries()).hasSize(2);
        assertThat(result.bodyEnumerationSkipped()).isFalse();
        verify(request).parameters();
    }

    @Test
    void collectParameters_nullRequest_returnsEmpty() {
        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.collectParameters(null, false);
        assertThat(result.entries()).isEmpty();
        assertThat(result.bodyEnumerationSkipped()).isFalse();
    }

    @Test
    void collectParameters_includeBodyFalse_swallowsTypedAccessorThrows_andCollectsRest() {
        ParsedHttpParameter cookie = param("session", "abc", HttpParameterType.COOKIE);
        List<ParsedHttpParameter> cookieParams = List.of(cookie);
        HttpRequest request = mock(HttpRequest.class);
        when(request.hasParameters(HttpParameterType.URL)).thenReturn(true);
        when(request.parameters(HttpParameterType.URL)).thenThrow(new RuntimeException("malformed url params"));
        when(request.hasParameters(HttpParameterType.COOKIE)).thenReturn(true);
        when(request.parameters(HttpParameterType.COOKIE)).thenReturn(cookieParams);
        when(request.hasParameters(HttpParameterType.JSON)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML_ATTRIBUTE)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.MULTIPART_ATTRIBUTE)).thenReturn(false);

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.collectParameters(request, false);

        assertThat(result.entries()).hasSize(1);
        assertThat(result.bodyEnumerationSkipped()).isTrue();
        verify(request, never()).parameters();
    }

    @Test
    void recordParameterTelemetry_skippedBody_underThreshold_bumpsCounterOnly() throws Exception {
        HttpRequest request = mockRequest("POST", "https://example.test/binary-misdeclared");

        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterTelemetry(
                        request, ContentType.URL_ENCODED, /* retained */ 3, /* dropped */ 0,
                        /* bodyEnumerationSkipped */ true));

        assertThat(events).noneMatch(e -> e.message().contains("[ParameterCardinality]"));
        assertThat(ExportStats.getDocsWithSkippedBodyEnumeration()).isEqualTo(1);
        assertThat(ExportStats.getDocsOverParamsThreshold()).isZero();
        assertThat(ExportStats.getSynthesizedBodyParamsDropped()).isZero();
    }

    private static HttpRequest mockRequest(String method, String url) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn(method);
        when(request.url()).thenReturn(url);
        return request;
    }

    private static ParsedHttpParameter param(String name, String value, HttpParameterType type) {
        ParsedHttpParameter p = mock(ParsedHttpParameter.class);
        when(p.name()).thenReturn(name);
        when(p.value()).thenReturn(value);
        when(p.type()).thenReturn(type);
        return p;
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn(name);
        when(h.value()).thenReturn(value);
        return h;
    }

    private record LoggedEvent(String level, String message) {
        LoggedEvent {
            level = level == null ? "" : level;
            message = message == null ? "" : message;
        }
    }
}
