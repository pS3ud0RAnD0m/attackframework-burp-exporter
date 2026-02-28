package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.list;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.AttributeType;

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
                "body_length", "body_offset", "body", "body_content", "markers");
        assertThat(req.get("method")).isEqualTo("GET");
        assertThat(req.get("path")).isEqualTo("/path?q=1");
        assertThat(req.get("headers")).asInstanceOf(list(Object.class)).isEmpty();
    }

    @Test
    void buildDocument_responseHasExpectedShape() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) doc.get("response");
        assertThat(resp).isNotNull();
        assertThat(resp).containsKeys("status", "status_code_class", "reason_phrase", "http_version", "headers",
                "cookies", "mime_type", "body_length", "body_offset", "body", "body_content", "markers");
        assertThat(resp.get("status")).isEqualTo(200);
        assertThat(resp.get("status_code_class")).isEqualTo("CLASS_2XX_SUCCESS");
        assertThat(resp.get("reason_phrase")).isEqualTo("OK");
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
}
