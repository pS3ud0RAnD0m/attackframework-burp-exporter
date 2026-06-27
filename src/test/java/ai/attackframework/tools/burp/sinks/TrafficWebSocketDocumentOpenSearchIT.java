package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.pushAndAwaitIndexedDocument;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.mockito.Answers;

import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.testutils.OpenSearchTestConfig;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.websocket.Direction;

/**
 * Integration test: filtered proxy WebSocket traffic documents round-trip through OpenSearch.
 */
@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class TrafficWebSocketDocumentOpenSearchIT {

    private static final String BASE_URL = OpenSearchReachable.BASE_URL;
    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        MontoyaApiProvider.set(null);
        deleteIndex("traffic");
    }

    @Test
    void filteredProxyWebSocketDocument_indexesNestedWebSocketShape() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        false,
                        "",
                        true,
                        BASE_URL,
                        config.username(),
                        config.password(),
                        false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of(
                        "traffic",
                        Set.of(
                                "websocket.direction",
                                "websocket.payload.text",
                                "websocket.is_websocket",
                                "request.url.raw",
                                "burp.reporting_tool")));

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);

        Map<String, Object> built = buildProxyWebSocketDocument(api);
        Map<String, Object> stored = pushAndAwaitIndexedDocument(
                "traffic", built, state, "request.url.raw", "https://example.com/ws");
        assertThat(stored).containsKeys("meta", "burp", "request", "websocket");
        assertThat(stored).doesNotContainKey("response");
        Map<?, ?> websocket = nestedMap(stored, "websocket");
        assertThat(websocket.get("is_websocket")).isEqualTo(true);
        assertThat(websocket.get("direction")).isEqualTo("CLIENT_TO_SERVER");
        assertThat(websocket.containsKey("id")).isFalse();
        assertThat(websocket.containsKey("message_id")).isFalse();
        assertThat(nestedMap(websocket, "payload").get("text")).isEqualTo("ws-it");
        assertThat(nestedMap(nestedMap(stored, "request"), "url").get("raw")).isEqualTo("https://example.com/ws");
        assertThat(nestedMap(stored, "burp").get("reporting_tool")).isEqualTo("Proxy WebSocket");
    }

    private static Map<String, Object> buildProxyWebSocketDocument(MontoyaApi api) {
        ProxyWebSocketMessage ws = mock(ProxyWebSocketMessage.class);
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService svc = mock(HttpService.class);
        ByteArray payload = mock(ByteArray.class);
        when(svc.host()).thenReturn("example.com");
        when(svc.port()).thenReturn(443);
        when(svc.secure()).thenReturn(true);
        when(upgrade.httpService()).thenReturn(svc);
        when(upgrade.url()).thenReturn("https://example.com/ws");
        when(upgrade.httpVersion()).thenReturn("HTTP/1.1");
        when(upgrade.path()).thenReturn("/ws");
        when(upgrade.method()).thenReturn("GET");
        when(upgrade.pathWithoutQuery()).thenReturn("/ws");
        when(upgrade.query()).thenReturn("");
        when(upgrade.fileExtension()).thenReturn("");
        when(upgrade.headers()).thenReturn(List.of());
        when(upgrade.parameters()).thenReturn(List.of());
        when(upgrade.body()).thenReturn(null);
        when(upgrade.markers()).thenReturn(List.of());
        when(upgrade.contentType()).thenReturn(null);
        when(payload.getBytes()).thenReturn("ws-it".getBytes(StandardCharsets.UTF_8));
        when(ws.upgradeRequest()).thenReturn(upgrade);
        when(ws.id()).thenReturn(99);
        when(ws.webSocketId()).thenReturn(7);
        when(ws.listenerPort()).thenReturn(8080);
        when(ws.payload()).thenReturn(payload);
        when(ws.editedPayload()).thenReturn(null);
        when(ws.direction()).thenReturn(Direction.CLIENT_TO_SERVER);
        when(ws.time()).thenReturn(ZonedDateTime.now());
        when(ws.annotations()).thenReturn(null);
        return ProxyWebSocketIndexReporter.buildDocument(api, ws);
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }
}
