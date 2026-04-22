package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.call;
import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.ExportStats;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;

/**
 * Asserts that {@link TrafficHttpHandler#buildDocument} produces a document with the expected
 * top-level and nested shape for the traffic index mapping.
 */
class TrafficHttpHandlerDocumentTest {

    private final TrafficHttpHandler handler = new TrafficHttpHandler();
    private final HttpRequest request = mock(HttpRequest.class);
    private final HttpResponseReceived response = mock(HttpResponseReceived.class);
    private final HttpService service = mock(HttpService.class);

    {
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);

        when(request.url()).thenReturn("https://example.com/path?q=1");
        when(request.httpService()).thenReturn(service);
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/path?q=1");
        when(request.pathWithoutQuery()).thenReturn("/path");
        when(request.query()).thenReturn("q=1");
        when(request.fileExtension()).thenReturn("");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.bodyOffset()).thenReturn(0);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(ContentType.NONE);
        ByteArray requestBytes = byteArray("GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
        when(request.toByteArray()).thenReturn(requestBytes);

        when(response.initiatingRequest()).thenReturn(request);
        when(response.messageId()).thenReturn(1);
        when(response.toolSource()).thenReturn(null);
        when(response.annotations()).thenReturn(null);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.reasonPhrase()).thenReturn("OK");
        when(response.httpVersion()).thenReturn("HTTP/1.1");
        when(response.headers()).thenReturn(List.of());
        when(response.cookies()).thenReturn(List.of());
        when(response.mimeType()).thenReturn(MimeType.HTML);
        when(response.statedMimeType()).thenReturn(MimeType.HTML);
        when(response.inferredMimeType()).thenReturn(MimeType.HTML);
        when(response.body()).thenReturn(null);
        when(response.bodyOffset()).thenReturn(0);
        when(response.bodyToString()).thenReturn("");
        when(response.markers()).thenReturn(List.of());
        when(response.attributes(any(AttributeType[].class))).thenReturn(List.of());
        ByteArray responseBytes = byteArray("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        when(response.toByteArray()).thenReturn(responseBytes);
    }

    @Test
    void buildDocument_hasRequiredTopLevelKeys() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        assertThat(doc).containsKeys("url", "host", "port", "scheme", "http_version", "tool", "burp_in_scope",
                "message_id", "path", "method", "status", "mime_type", "repeater_tab_name",
                "repeater_group_name", "request", "response", "document_meta");
    }

    @Test
    void buildDocument_reservesRepeaterMetadataFields_forFutureLiveEnrichment() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        assertThat(doc.get("repeater_tab_name")).isNull();
        assertThat(doc.get("repeater_group_name")).isNull();
    }

    @Test
    void buildDocument_writesLiveRepeaterMetadata_whenProvided() {
        Map<String, Object> doc = handler.buildDocument(
                response,
                request,
                true,
                1L,
                2L,
                ToolType.REPEATER,
                new RepeaterMetadataFields.Metadata("Tab 7", "Group X"));

        assertThat(doc.get("repeater_tab_name")).isEqualTo("Tab 7");
        assertThat(doc.get("repeater_group_name")).isEqualTo("Group X");
    }

    @Test
    void buildDocument_requestHasExpectedShape() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> req = nestedMap(doc, "request");
        assertThat(req).isNotNull();
        assertContainsKeys(req, "method", "path", "path_without_query", "query", "headers", "parameters",
                "body", "markers");
        Map<?, ?> reqBody = nestedMap(req, "body");
        assertContainsKeys(reqBody, "length", "offset", "b64", "text");
        Map<?, ?> reqHeaders = nestedMap(req, "headers");
        assertContainsKeys(reqHeaders, "full");
        assertThat(reqHeaders.get("full")).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class)).isEmpty();
        assertThat(req.get("method")).isEqualTo("GET");
        assertThat(req.get("path")).isEqualTo("/path?q=1");
    }

    @Test
    void buildDocument_usesRawRequestLineFallback_whenRequestAccessorsThrow() {
        when(request.url()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.method()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.path()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.pathWithoutQuery()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.query()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.fileExtension()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.httpVersion()).thenThrow(new IllegalArgumentException("URL is invalid."));
        ByteArray malformedRequestBytes = byteArray("POST /fallback/path?q=1 HTTP/2\r\nHost: example.com\r\n\r\n");
        when(request.toByteArray()).thenReturn(malformedRequestBytes);

        Map<String, Object> doc = handler.buildDocument(response, request, true);

        assertThat(doc.get("url")).isEqualTo("https://example.com/fallback/path?q=1");
        assertThat(doc.get("method")).isEqualTo("POST");
        assertThat(doc.get("path")).isEqualTo("/fallback/path?q=1");
        assertThat(doc.get("http_version")).isEqualTo("HTTP/2");

        Map<?, ?> req = nestedMap(doc, "request");
        assertThat(req.get("method")).isEqualTo("POST");
        assertThat(req.get("path")).isEqualTo("/fallback/path?q=1");
        assertThat(req.get("path_without_query")).isEqualTo("/fallback/path");
        assertThat(req.get("query")).isEqualTo("q=1");
        assertThat(req.get("http_version")).isEqualTo("HTTP/2");
    }

    @Test
    void buildDocument_responseHasExpectedShape() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> resp = nestedMap(doc, "response");
        assertThat(resp).isNotNull();
        assertContainsKeys(resp, "status", "status_code_class", "reason_phrase", "http_version", "headers",
                "cookies", "mime_type", "body", "markers");
        Map<?, ?> respBody = nestedMap(resp, "body");
        assertContainsKeys(respBody, "length", "offset", "b64", "text");
        Map<?, ?> respHeaders = nestedMap(resp, "headers");
        assertContainsKeys(respHeaders, "full");
        assertThat(respHeaders.get("full")).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class)).isEmpty();
        assertThat(resp.get("status")).isEqualTo(200);
        assertThat(resp.get("status_code_class")).isEqualTo("CLASS_2XX_SUCCESS");
        assertThat(resp.get("reason_phrase")).isEqualTo("OK");
    }

    @Test
    void buildDocument_responseBodyText_present_forTextAndNotCompressed() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("<html>ok</html>".getBytes(StandardCharsets.UTF_8));
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("text/html; charset=UTF-8");
        when(response.headers()).thenReturn(List.of(ct));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isEqualTo("<html>ok</html>");
    }

    @Test
    void buildDocument_responseBodyText_present_forVendorPlusJson() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("{\"k\":1}".getBytes(StandardCharsets.UTF_8));
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("application/vnd.api+json");
        when(response.headers()).thenReturn(List.of(ct));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isEqualTo("{\"k\":1}");
    }

    @Test
    void buildDocument_responseBodyText_null_whenCompressed() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("<html>ok</html>".getBytes(StandardCharsets.UTF_8));
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("text/html; charset=UTF-8");
        HttpHeader ce = mock(HttpHeader.class);
        when(ce.name()).thenReturn("Content-Encoding");
        when(ce.value()).thenReturn("gzip");
        when(response.headers()).thenReturn(List.of(ct, ce));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isNull();
    }

    @Test
    void buildDocument_responseBodyText_null_forBinaryType() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn(new byte[] {0x00, 0x01, 0x02, 0x03});
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("application/octet-stream");
        when(response.headers()).thenReturn(List.of(ct));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isNull();
    }

    @Test
    void buildDocument_responseBodyText_respectsIso88591Charset() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("caf\u00e9".getBytes(StandardCharsets.ISO_8859_1));
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("text/plain; charset=ISO-8859-1");
        when(response.headers()).thenReturn(List.of(ct));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isEqualTo("caf\u00e9");
    }

    @Test
    void buildDocument_responseBodyText_present_whenContentTypeMissing_butMontoyaMimeIsTextual() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
        when(response.body()).thenReturn(body);
        when(response.headers()).thenReturn(List.of());
        when(response.mimeType()).thenReturn(MimeType.JSON);
        when(response.statedMimeType()).thenReturn(null);
        when(response.inferredMimeType()).thenReturn(MimeType.JSON);

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isEqualTo("{\"ok\":true}");
    }

    @Test
    void buildDocument_requestBodyText_present_forCustomPhpType_whenTextLike() {
        ByteArray reqBodyBytes = mock(ByteArray.class);
        when(reqBodyBytes.getBytes()).thenReturn("<?php echo 1; ?>".getBytes(StandardCharsets.UTF_8));
        when(request.body()).thenReturn(reqBodyBytes);
        HttpHeader reqCt = mock(HttpHeader.class);
        when(reqCt.name()).thenReturn("Content-Type");
        when(reqCt.value()).thenReturn("application/php; charset=UTF-8");
        when(request.headers()).thenReturn(List.of(reqCt));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> reqBody = nestedMap(nestedMap(doc, "request"), "body");
        assertThat(reqBody.get("text")).isEqualTo("<?php echo 1; ?>");
    }

    @Test
    void buildDocument_requestBodyText_present_forUnknownCustomType_whenTextLike() {
        ByteArray reqBodyBytes = mock(ByteArray.class);
        when(reqBodyBytes.getBytes()).thenReturn("user=alice&role=admin".getBytes(StandardCharsets.UTF_8));
        when(request.body()).thenReturn(reqBodyBytes);
        HttpHeader reqCt = mock(HttpHeader.class);
        when(reqCt.name()).thenReturn("Content-Type");
        when(reqCt.value()).thenReturn("application/dbm");
        when(request.headers()).thenReturn(List.of(reqCt));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> reqBody = nestedMap(nestedMap(doc, "request"), "body");
        assertThat(reqBody.get("text")).isEqualTo("user=alice&role=admin");
    }

    @Test
    void buildDocument_documentMetaHasSchemaAndVersion() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> meta = nestedMap(doc, "document_meta");
        assertThat(meta).isNotNull();
        assertContainsKeys(meta, "schema_version", "extension_version", "indexed_at");
        assertThat(meta.get("schema_version")).isEqualTo("1");
    }

    @Test
    void buildOrphanResponse_matchesCurrentTrafficResponseShape() {
        Map<?, ?> responseDoc = map(callStatic(TrafficHttpHandler.class, "buildOrphanResponse"));

        assertContainsKeys(responseDoc,
                "status", "status_code_class", "reason_phrase", "http_version", "headers", "cookies",
                "mime_type", "stated_mime_type", "inferred_mime_type", "body", "markers");
        assertMissingKeys(responseDoc, "header_names", "body_length", "body_offset");

        Map<?, ?> headers = nestedMap(responseDoc, "headers");
        assertContainsKeys(headers, "full", "names", "etag", "last_modified", "content_location");
        assertThat(headers.get("full")).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class)).isEmpty();
        assertThat(headers.get("names")).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class)).isEmpty();

        Map<?, ?> body = nestedMap(responseDoc, "body");
        assertThat(body.get("length")).isEqualTo(0);
        assertThat(body.get("offset")).isEqualTo(0);
        assertThat(body.get("b64")).isNull();
        assertThat(body.get("text")).isNull();
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        return map(parent.get(key));
    }

    private static Map<?, ?> map(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
    }

    private static void assertContainsKeys(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            assertThat(map.containsKey(key)).isTrue();
        }
    }

    private static void assertMissingKeys(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            assertThat(map.containsKey(key)).isFalse();
        }
    }

    @Test
    void resolveResponseToolType_prefersResponseToolTypeWhenPresent() {
        ToolSource responseSource = mock(ToolSource.class);
        when(responseSource.toolType()).thenReturn(ToolType.REPEATER);
        when(response.toolSource()).thenReturn(responseSource);

            assertThat(TrafficHttpHandler.resolveResponseToolType(response, ToolType.PROXY))
                .isEqualTo(ToolType.REPEATER);
    }

    @Test
    void resolveResponseToolType_fallsBackToRequestToolTypeWhenResponseMissing() {
        when(response.toolSource()).thenReturn(null);

        assertThat(TrafficHttpHandler.resolveResponseToolType(response, ToolType.PROXY))
                .isEqualTo(ToolType.PROXY);
    }

    @Test
    void resolveResponseToolType_returnsNullWhenBothMissing() {
        when(response.toolSource()).thenReturn(null);

        assertThat(TrafficHttpHandler.resolveResponseToolType(response, null)).isNull();
    }

    @Test
    void resolveRequestStageRepeaterMetadata_returnsTrackedMetadata_forRepeaterTraffic() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            null),
                    new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha"),
                    now);

            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(request, ToolType.REPEATER))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha"));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveRequestStageRepeaterMetadata_fallsBackToCurrentRepeaterMetadata_whenTrackerEmpty() {
        RepeaterLiveMetadataTracker.clear();
        try {
            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> new RepeaterMetadataFields.Metadata("GetUserToken", null)))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("GetUserToken", null));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveRequestStageRepeaterMetadata_doesNotCallFallbackSupplier_whenTrackerResolves() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            AtomicInteger fallbackCalls = new AtomicInteger();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            null),
                    new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha"),
                    now);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> {
                        fallbackCalls.incrementAndGet();
                        return new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group");
                    });

            assertThat(resolved).isEqualTo(new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha"));
            assertThat(fallbackCalls).hasValue(0);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveRequestStageRepeaterMetadata_returnsEmpty_whenTrackerIsAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            AtomicInteger fallbackCalls = new AtomicInteger();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB"),
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> {
                        fallbackCalls.incrementAndGet();
                        return new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group");
                    });

            assertThat(resolved).isEqualTo(RepeaterMetadataFields.Metadata.empty());
            assertThat(fallbackCalls).hasValue(0);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveRequestStageResolution_keepsUiSnapshot_whenTrackerIsAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            AtomicInteger fallbackCalls = new AtomicInteger();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB"),
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            TrafficHttpHandlerSupport.RequestStageResolution resolution =
                    TrafficHttpHandler.resolveRequestStageResolution(
                            request,
                            ToolType.REPEATER,
                            () -> {
                                fallbackCalls.incrementAndGet();
                                return new RepeaterMetadataFields.Metadata("ApplyCode", null);
                            });

            assertThat(resolution.metadata()).isEqualTo(RepeaterMetadataFields.Metadata.empty());
            assertThat(resolution.uiSnapshot()).isEqualTo(new RepeaterMetadataFields.Metadata("ApplyCode", null));
            assertThat(fallbackCalls).hasValue(1);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveRequestStageRepeaterMetadata_prefersExactRequestIdentity_whenHashesAreAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            AtomicInteger fallbackCalls = new AtomicInteger();
            HttpRequestResponse first = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            HttpRequestResponse second = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB");
            RepeaterLiveMetadataTracker.observe(
                    first,
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    second,
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    first.request(),
                    ToolType.REPEATER,
                    () -> {
                        fallbackCalls.incrementAndGet();
                        return new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group");
                    });

            assertThat(resolved).isEqualTo(new RepeaterMetadataFields.Metadata("Tab One", "Group One"));
            assertThat(fallbackCalls).hasValue(0);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void repeaterMetadataSourceCounters_recordRequestIdentityAndUiFallbackPaths() {
        ExportStats.resetForTests();
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            HttpRequestResponse tracked = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    null);
            RepeaterMetadataFields.Metadata trackedMetadata =
                    new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha");
            RepeaterLiveMetadataTracker.observe(tracked, trackedMetadata, now);

            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    tracked.request(),
                    ToolType.REPEATER)).isEqualTo(trackedMetadata);

            RepeaterLiveMetadataTracker.clear();

            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", null)))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Fallback Tab", null));

            assertThat(ExportStats.getRepeaterMetadataSourceCount("request_identity")).isEqualTo(1);
            assertThat(ExportStats.getRepeaterMetadataSourceCount("ui_fallback")).isEqualTo(1);
        } finally {
            RepeaterLiveMetadataTracker.clear();
            ExportStats.resetForTests();
        }
    }

    @Test
    void repeaterMetadataSourceCounters_recordHashAndReusePaths() {
        ExportStats.resetForTests();
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                    new RepeaterMetadataFields.Metadata("Hash Tab", "Hash Group"),
                    now);

            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group")))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Hash Tab", "Hash Group"));
            assertThat(TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    RepeaterMetadataFields.Metadata.empty(),
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group")))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Hash Tab", "Hash Group"));

            RepeaterLiveMetadataTracker.clear();

            assertThat(TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"),
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group")))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"));

            assertThat(ExportStats.getRepeaterMetadataSourceCount("request_hash")).isEqualTo(1);
            assertThat(ExportStats.getRepeaterMetadataSourceCount("exchange_hash")).isEqualTo(1);
            assertThat(ExportStats.getRepeaterMetadataSourceCount("request_stage_reuse")).isEqualTo(1);
        } finally {
            RepeaterLiveMetadataTracker.clear();
            ExportStats.resetForTests();
        }
    }

    @Test
    void repeaterMetadataSourceCounters_recordAmbiguousNullPath() {
        ExportStats.resetForTests();
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB"),
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group")))
                    .isEqualTo(RepeaterMetadataFields.Metadata.empty());
            assertThat(ExportStats.getRepeaterMetadataSourceCount("ambiguous_null")).isEqualTo(1);
        } finally {
            RepeaterLiveMetadataTracker.clear();
            ExportStats.resetForTests();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_prefersExchangeMatch_overRequestStageFallback() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                    new RepeaterMetadataFields.Metadata("Live Tab", "Live Group"),
                    now);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group"));

            assertThat(resolved).isEqualTo(new RepeaterMetadataFields.Metadata("Live Tab", "Live Group"));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_doesNotCallFallbackSupplier_whenRequestStageMetadataPresent() {
        RepeaterLiveMetadataTracker.clear();
        try {
            AtomicInteger fallbackCalls = new AtomicInteger();

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"),
                    () -> {
                        fallbackCalls.incrementAndGet();
                        return new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group");
                    });

            assertThat(resolved)
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"));
            assertThat(fallbackCalls).hasValue(0);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_fallsBackToCurrentRepeaterMetadata_whenTrackerEmpty() {
        RepeaterLiveMetadataTracker.clear();
        try {
            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    RepeaterMetadataFields.Metadata.empty(),
                    () -> new RepeaterMetadataFields.Metadata("GetUserToken", null));

            assertThat(resolved).isEqualTo(new RepeaterMetadataFields.Metadata("GetUserToken", null));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_reusesRequestStageUiSnapshot_whenRequestWasAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            TrafficHttpHandlerSupport.RequestStageResolution requestStageResolution =
                    TrafficHttpHandlerSupport.RequestStageResolution.ambiguous(
                            RepeaterMetadataTraceLabels.REQUEST_HASH,
                            new RepeaterMetadataFields.Metadata("ApplyCode", null));

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    requestStageResolution,
                    () -> new RepeaterMetadataFields.Metadata("380", null));

            assertThat(resolved).isEqualTo(new RepeaterMetadataFields.Metadata("ApplyCode", null));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_fallsBackToRequestStageMetadata_whenExchangeMatchAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            HttpRequestResponse exchange = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            RepeaterLiveMetadataTracker.observe(
                    exchange,
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    exchange,
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"));

            assertThat(resolved)
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_returnsEmpty_whenExchangeAndRequestAreAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            HttpRequestResponse first = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            HttpRequestResponse second = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            RepeaterLiveMetadataTracker.observe(
                    first,
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    second,
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    RepeaterMetadataFields.Metadata.empty(),
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group"));

            assertThat(resolved).isEqualTo(RepeaterMetadataFields.Metadata.empty());
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void buildOrphanDocumentSkeleton_writesRepeaterRequestStageMetadata_forRequestOnlyExports() {
        @SuppressWarnings("unchecked")
        Map<String, Object> skeleton = (Map<String, Object>) call(
                handler,
                "buildOrphanDocumentSkeleton",
                requestToBeSent(
                        "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        77,
                        ToolType.REPEATER),
                1L,
                new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha"));

        assertThat(skeleton.get("repeater_tab_name")).isEqualTo("Repeater Tab");
        assertThat(skeleton.get("repeater_group_name")).isEqualTo("Group Alpha");
    }

    @Test
    void buildOrphanDocumentSkeleton_keepsRepeaterMetadataNull_forNonRepeaterTraffic_evenWhenTrackerHasData() {
        RepeaterLiveMetadataTracker.clear();
        try {
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            null),
                    new RepeaterMetadataFields.Metadata("Tracked Tab", "Tracked Group"),
                    System.currentTimeMillis());

            @SuppressWarnings("unchecked")
            Map<String, Object> skeleton = (Map<String, Object>) call(
                    handler,
                    "buildOrphanDocumentSkeleton",
                    requestToBeSent(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            78,
                            ToolType.PROXY),
                    1L,
                    TrafficHttpHandler.resolveRequestStageRepeaterMetadata(request, ToolType.PROXY));

            assertThat(skeleton.get("repeater_tab_name")).isNull();
            assertThat(skeleton.get("repeater_group_name")).isNull();
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    private static HttpRequestResponse requestResponse(String rawRequest, String rawResponse) {
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        HttpRequest trackedRequest = mock(HttpRequest.class);
        ByteArray trackedRequestBytes = byteArray(rawRequest);
        when(trackedRequest.toByteArray()).thenReturn(trackedRequestBytes);
        when(requestResponse.request()).thenReturn(trackedRequest);
        if (rawResponse != null) {
            HttpResponseReceived trackedResponse = mock(HttpResponseReceived.class);
            ByteArray trackedResponseBytes = byteArray(rawResponse);
            when(trackedResponse.toByteArray()).thenReturn(trackedResponseBytes);
            when(requestResponse.response()).thenReturn(trackedResponse);
        }
        return requestResponse;
    }

    private static ByteArray byteArray(String value) {
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.getBytes()).thenReturn(value.getBytes(StandardCharsets.UTF_8));
        return bytes;
    }

    private static HttpRequestToBeSent requestToBeSent(String rawRequest, int messageId, ToolType toolType) {
        HttpRequestToBeSent request = mock(HttpRequestToBeSent.class);
        HttpService service = mock(HttpService.class);
        ToolSource toolSource = mock(ToolSource.class);
        ByteArray requestBytes = byteArray(rawRequest);

        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(toolSource.toolType()).thenReturn(toolType);

        when(request.toolSource()).thenReturn(toolSource);
        when(request.messageId()).thenReturn(messageId);
        when(request.isInScope()).thenReturn(true);
        when(request.url()).thenReturn("https://example.com/path?q=1");
        when(request.httpService()).thenReturn(service);
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/path?q=1");
        when(request.pathWithoutQuery()).thenReturn("/path");
        when(request.query()).thenReturn("q=1");
        when(request.fileExtension()).thenReturn("");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.bodyOffset()).thenReturn(0);
        when(request.markers()).thenReturn(List.of());
        when(request.annotations()).thenReturn(null);
        when(request.contentType()).thenReturn(ContentType.NONE);
        when(request.toByteArray()).thenReturn(requestBytes);
        return request;
    }
}
