package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.websocket.Direction;

class ProxyWebSocketIndexReporterTest {

    @AfterEach
    void resetRuntimeConfig() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "http://opensearch.url:9200"),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void buildDocument_includesExpectedWebSocketFields() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, true, "http://opensearch.url:9200"),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("PROXY"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);

        ProxyWebSocketMessage ws = mock(ProxyWebSocketMessage.class);
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService svc = mock(HttpService.class);
        ByteArray payload = mock(ByteArray.class);
        ByteArray editedPayload = mock(ByteArray.class);

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

        when(payload.getBytes()).thenReturn("hello".getBytes(StandardCharsets.UTF_8));
        when(editedPayload.getBytes()).thenReturn("HELLO".getBytes(StandardCharsets.UTF_8));

        when(ws.upgradeRequest()).thenReturn(upgrade);
        when(ws.id()).thenReturn(12);
        when(ws.webSocketId()).thenReturn(7);
        when(ws.listenerPort()).thenReturn(8080);
        when(ws.payload()).thenReturn(payload);
        when(ws.editedPayload()).thenReturn(editedPayload);
        when(ws.direction()).thenReturn(Direction.CLIENT_TO_SERVER);
        when(ws.time()).thenReturn(ZonedDateTime.now());
        when(ws.annotations()).thenReturn(null);

        Map<String, Object> doc = ProxyWebSocketIndexReporter.buildDocument(api, ws);

        assertThat(doc).isNotNull();
        assertThat(doc.get("tool_type")).isEqualTo("PROXY_WEBSOCKET");
        assertThat(doc.get("websocket_id")).isEqualTo(7);
        assertThat(doc.get("ws_message_id")).isEqualTo(12);
        assertThat(doc.get("ws_direction")).isEqualTo("CLIENT_TO_SERVER");
        assertThat(doc.get("listener_port")).isEqualTo(8080);
        assertThat(doc.get("ws_payload")).isNotNull();
        assertThat(doc.get("ws_payload_text")).isEqualTo("hello");
        assertThat(doc.get("ws_edited")).isEqualTo(true);
        assertThat(doc.get("ws_edited_payload")).isNotNull();
        assertThat(doc.get("ws_upgrade_request")).isInstanceOf(Map.class);
    }
}
