package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;

/**
 * Asserts that {@link OpenSearchTrafficHandler#buildDocument} produces a document
 * with the expected top-level and nested shape for the traffic index mapping.
 */
class OpenSearchTrafficHandlerDocumentTest {

    private OpenSearchTrafficHandler handler;
    private HttpRequest request;
    private HttpResponseReceived response;
    private HttpService service;

    @BeforeEach
    void setUp() {
        handler = new OpenSearchTrafficHandler();
        request = mock(HttpRequest.class);
        response = mock(HttpResponseReceived.class);
        service = mock(HttpService.class);

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
    }

    @Test
    void buildDocument_hasRequiredTopLevelKeys() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        assertThat(doc).containsKeys("url", "host", "port", "scheme", "http_version", "tool", "in_scope",
                "message_id", "path", "method", "status", "mime_type", "request", "response", "document_meta");
    }

    @Test
    void buildDocument_requestHasExpectedShape() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        @SuppressWarnings("unchecked")
        Map<String, Object> req = (Map<String, Object>) doc.get("request");
        assertThat(req).isNotNull();
        assertThat(req).containsKeys("method", "path", "path_without_query", "query", "headers", "parameters",
                "body", "markers");
        @SuppressWarnings("unchecked")
        Map<String, Object> reqBody = (Map<String, Object>) req.get("body");
        assertThat(reqBody).isNotNull().containsKeys("length", "offset", "b64", "text");
        @SuppressWarnings("unchecked")
        Map<String, Object> reqHeaders = (Map<String, Object>) req.get("headers");
        assertThat(reqHeaders).isNotNull().containsKey("full");
        assertThat(reqHeaders.get("full")).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class)).isEmpty();
        assertThat(req.get("method")).isEqualTo("GET");
        assertThat(req.get("path")).isEqualTo("/path?q=1");
    }

    @Test
    void buildDocument_responseHasExpectedShape() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) doc.get("response");
        assertThat(resp).isNotNull();
        assertThat(resp).containsKeys("status", "status_code_class", "reason_phrase", "http_version", "headers",
                "cookies", "mime_type", "body", "markers");
        @SuppressWarnings("unchecked")
        Map<String, Object> respBody = (Map<String, Object>) resp.get("body");
        assertThat(respBody).isNotNull().containsKeys("length", "offset", "b64", "text");
        @SuppressWarnings("unchecked")
        Map<String, Object> respHeaders = (Map<String, Object>) resp.get("headers");
        assertThat(respHeaders).isNotNull().containsKey("full");
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
        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) doc.get("response");
        @SuppressWarnings("unchecked")
        Map<String, Object> respBody = (Map<String, Object>) resp.get("body");
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
        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) doc.get("response");
        @SuppressWarnings("unchecked")
        Map<String, Object> respBody = (Map<String, Object>) resp.get("body");
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
        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) doc.get("response");
        @SuppressWarnings("unchecked")
        Map<String, Object> respBody = (Map<String, Object>) resp.get("body");
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
        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) doc.get("response");
        @SuppressWarnings("unchecked")
        Map<String, Object> respBody = (Map<String, Object>) resp.get("body");
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
        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) doc.get("response");
        @SuppressWarnings("unchecked")
        Map<String, Object> respBody = (Map<String, Object>) resp.get("body");
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
        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) doc.get("response");
        @SuppressWarnings("unchecked")
        Map<String, Object> respBody = (Map<String, Object>) resp.get("body");
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
        @SuppressWarnings("unchecked")
        Map<String, Object> req = (Map<String, Object>) doc.get("request");
        @SuppressWarnings("unchecked")
        Map<String, Object> reqBody = (Map<String, Object>) req.get("body");
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
        @SuppressWarnings("unchecked")
        Map<String, Object> req = (Map<String, Object>) doc.get("request");
        @SuppressWarnings("unchecked")
        Map<String, Object> reqBody = (Map<String, Object>) req.get("body");
        assertThat(reqBody.get("text")).isEqualTo("user=alice&role=admin");
    }

    @Test
    void buildDocument_documentMetaHasSchemaAndVersion() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) doc.get("document_meta");
        assertThat(meta).isNotNull();
        assertThat(meta).containsKeys("schema_version", "extension_version", "indexed_at");
        assertThat(meta.get("schema_version")).isEqualTo("1");
    }

    @Test
    void resolveResponseToolType_prefersResponseToolTypeWhenPresent() {
        ToolSource responseSource = mock(ToolSource.class);
        when(responseSource.toolType()).thenReturn(ToolType.REPEATER);
        when(response.toolSource()).thenReturn(responseSource);

        assertThat(OpenSearchTrafficHandler.resolveResponseToolType(response, ToolType.PROXY))
                .isEqualTo(ToolType.REPEATER);
    }

    @Test
    void resolveResponseToolType_fallsBackToRequestToolTypeWhenResponseMissing() {
        when(response.toolSource()).thenReturn(null);

        assertThat(OpenSearchTrafficHandler.resolveResponseToolType(response, ToolType.PROXY))
                .isEqualTo(ToolType.PROXY);
    }

    @Test
    void resolveResponseToolType_returnsNullWhenBothMissing() {
        when(response.toolSource()).thenReturn(null);

        assertThat(OpenSearchTrafficHandler.resolveResponseToolType(response, null)).isNull();
    }
}
