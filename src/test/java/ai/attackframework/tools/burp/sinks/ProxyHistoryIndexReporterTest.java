package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Unit tests for {@link ProxyHistoryIndexReporter}: no-op paths when proxy_history
 * is not selected or export is not running (no OpenSearch or MontoyaApi required).
 */
class ProxyHistoryIndexReporterTest {

    private static void resetRuntimeConfig() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        ));
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void pushSnapshotNow_doesNotThrow_whenProxyHistoryNotInTrafficTypes() {
        try {
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of("traffic"), "all", List.of(),
                    new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy", "repeater"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            assertThatCode(() -> ProxyHistoryIndexReporter.pushSnapshotNow()).doesNotThrowAnyException();
        } finally {
            resetRuntimeConfig();
        }
    }

    @Test
    void pushSnapshotNow_doesNotThrow_whenExportNotRunning() {
        try {
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of("traffic"), "all", List.of(),
                    new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy_history"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            assertThatCode(() -> ProxyHistoryIndexReporter.pushSnapshotNow()).doesNotThrowAnyException();
        } finally {
            resetRuntimeConfig();
        }
    }

    @Test
    void pushSnapshotNow_returnsImmediately_withoutBlocking() throws InterruptedException {
        try {
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of("traffic"), "all", List.of(),
                    new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy_history"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            long start = System.currentTimeMillis();
            ProxyHistoryIndexReporter.pushSnapshotNow();
            long elapsed = System.currentTimeMillis() - start;
            assertThat(elapsed).isLessThan(500);
        } finally {
            resetRuntimeConfig();
        }
    }

    @Test
    void buildDocument_survivesMalformedRequest_andReconstructsUrl() {
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(false);

        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenThrow(new IllegalStateException("URL is invalid."));
        when(request.method()).thenReturn("POST");
        when(request.path()).thenReturn("/api/orders");
        when(request.pathWithoutQuery()).thenReturn("/api/orders");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn("shop.example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);

        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        when(item.finalRequest()).thenReturn(request);
        when(item.httpService()).thenReturn(service);
        when(item.id()).thenReturn(42);
        when(item.listenerPort()).thenReturn(8080);
        when(item.edited()).thenReturn(false);
        when(item.annotations()).thenReturn(null);
        when(item.response()).thenReturn(null);

        Map<?, ?> doc = (Map<?, ?>) callStatic(ProxyHistoryIndexReporter.class, "buildDocument", api, item);

        assertThat(doc).isNotNull();
        assertThat(doc.get("url")).isEqualTo("https://shop.example.com/api/orders");
        assertThat(doc.get("method")).isEqualTo("POST");
        assertThat(doc.get("tool_type")).isEqualTo("PROXY_HISTORY");
        assertThat(doc.get("path")).isEqualTo("/api/orders");
        assertThat(doc.get("burp_in_scope")).isEqualTo(false);
    }

    @Test
    void emptyResponseDoc_matchesCurrentTrafficResponseShape() {
        Map<?, ?> responseDoc = map(callStatic(ProxyHistoryIndexReporter.class, "emptyResponseDoc"));

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
}
