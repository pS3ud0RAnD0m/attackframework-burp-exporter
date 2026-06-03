package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.opensearch.client.opensearch.OpenSearchClient;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.testutils.OpenSearchTestConfig;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.ExportDocumentIdentity;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
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
class TrafficWebSocketDocumentOpenSearchIT {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String BASE_URL = OpenSearchReachable.BASE_URL;
    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        MontoyaApiProvider.set(null);
        try {
            OpenSearchReachable.getClient().indices().delete(
                    new DeleteIndexRequest.Builder().index(trafficIndexName()).build());
        } catch (IOException | RuntimeException e) {
            Logger.logError("[TrafficWebSocketDocumentOpenSearchIT] cleanup failed", e);
        }
    }

    @Test
    void filteredProxyWebSocketDocument_indexesNestedWebSocketShape() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        OpenSearchReachable.createSelectedIndexes(List.of("traffic"));
        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(false);
        RuntimeConfig.updateState(new ConfigState.State(
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
                                "request.url",
                                "burp.reporting_tool"))));

        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(true);
        MontoyaApiProvider.set(api);

        Map<String, Object> built = buildProxyWebSocketDocument(api);
        PreparedExportDocument prepared =
                ExportDocumentIdentity.prepare(trafficIndexName(), "traffic", built);
        int pushed = OpenSearchClientWrapper.pushBulk(
                BASE_URL, trafficIndexName(), "traffic", List.of(prepared.document()));
        assertThat(pushed).isEqualTo(1);

        Map<String, Object> stored = awaitDocumentByExportId(prepared.exportId());
        assertThat(stored).containsKeys("meta", "burp", "request", "websocket");
        assertThat(stored).doesNotContainKey("response");
        Map<?, ?> websocket = nestedMap(stored, "websocket");
        assertThat(websocket.get("is_websocket")).isEqualTo(true);
        assertThat(websocket.get("direction")).isEqualTo("CLIENT_TO_SERVER");
        assertThat(websocket.containsKey("id")).isFalse();
        assertThat(websocket.containsKey("message_id")).isFalse();
        assertThat(nestedMap(websocket, "payload").get("text")).isEqualTo("ws-it");
        assertThat(nestedMap(stored, "request").get("url")).isEqualTo("https://example.com/ws");
        assertThat(nestedMap(stored, "burp").get("reporting_tool")).isEqualTo("Proxy WebSocket");
    }

    private static String trafficIndexName() {
        return IndexNaming.indexNameForShortName("traffic");
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

    private static Map<String, Object> awaitDocumentByExportId(String exportId) {
        OpenSearchClient client = OpenSearchReachable.getClient();
        SearchRequest request = new SearchRequest.Builder()
                .index(trafficIndexName())
                .size(5)
                .build();
        for (int attempt = 0; attempt < 80; attempt++) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(trafficIndexName()).build());
            } catch (IOException | RuntimeException ignored) {
                // best-effort refresh
            }
            try {
                SearchResponse<JsonNode> response = client.search(request, JsonNode.class);
                for (var hit : response.hits().hits()) {
                    JsonNode sourceNode = hit.source();
                    if (sourceNode == null) {
                        continue;
                    }
                    Map<String, Object> source =
                            JSON.convertValue(sourceNode, new TypeReference<Map<String, Object>>() { });
                    Map<?, ?> meta = nestedMap(source, "meta");
                    if (exportId.equals(meta.get("export_id"))) {
                        return source;
                    }
                }
            } catch (IOException | RuntimeException e) {
                throw new AssertionError("Search failed: " + e.getMessage(), e);
            }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(250));
        }
        throw new AssertionError("No traffic document indexed for export_id=" + exportId);
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }
}
