package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.nestedMap;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.pushAndAwaitIndexedDocument;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.mockito.Answers;

import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.websocket.Direction;

@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class ToolWebSocketLiveDocumentOpenSearchIT {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    public void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        MontoyaApiProvider.set(null);
        deleteIndex("traffic");
    }

    @Test
    void liveToolWebSocket_partialFieldSelection_indexesNestedShape() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);

        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of(
                        "traffic",
                        Set.of(
                                "websocket.payload.text",
                                "websocket.is_websocket",
                                "burp.reporting_tool",
                                "request.url.raw")));

        HttpRequest upgrade = mockUpgradeRequest();
        Map<String, Object> built = ToolWebSocketLiveHandler.buildLiveDocument(
                ToolType.REPEATER,
                upgrade,
                "live-ws-it".getBytes(StandardCharsets.UTF_8),
                Direction.CLIENT_TO_SERVER);
        assertThat(built).isNotNull();

        Map<String, Object> stored = pushAndAwaitIndexedDocument(
                "traffic", built, state, "request.url.raw", "https://example.com/ws-live");

        assertThat(stored).containsKeys("meta", "burp", "request", "websocket");
        assertThat(stored).doesNotContainKey("response");
        assertThat(nestedMap(stored, "burp").get("reporting_tool")).isEqualTo("Repeater");
        assertThat(nestedMap(nestedMap(stored, "request"), "url").get("raw"))
                .isEqualTo("https://example.com/ws-live");
        Map<?, ?> websocket = nestedMap(stored, "websocket");
        assertThat(websocket.get("is_websocket")).isEqualTo(true);
        assertThat(websocket.get("id")).isNull();
        assertThat(websocket.get("message_id")).isNull();
        assertThat(nestedMap(websocket, "payload").get("text")).isEqualTo("live-ws-it");
        assertThat(websocket.containsKey("direction")).isFalse();
    }

    private static HttpRequest mockUpgradeRequest() {
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        when(upgrade.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(upgrade.url()).thenReturn("https://example.com/ws-live");
        when(upgrade.httpVersion()).thenReturn("HTTP/1.1");
        when(upgrade.path()).thenReturn("/ws-live");
        when(upgrade.method()).thenReturn("GET");
        when(upgrade.pathWithoutQuery()).thenReturn("/ws-live");
        when(upgrade.query()).thenReturn("");
        when(upgrade.fileExtension()).thenReturn("");
        when(upgrade.headers()).thenReturn(List.of());
        when(upgrade.parameters()).thenReturn(List.of());
        when(upgrade.body()).thenReturn(null);
        when(upgrade.markers()).thenReturn(List.of());
        when(upgrade.contentType()).thenReturn(null);
        return upgrade;
    }
}
