package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.awaitDocumentByExportId;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.nestedMap;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.pushOneDocument;
import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

@Tag("integration")
class RepeaterPartialFieldSelectionOpenSearchIT {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        RepeaterTabsIndexReporter.clearSessionState();
        deleteIndex("traffic");
    }

    @Test
    void partialRepeaterFieldSelection_indexesNestedBurpRepeaterLeaves() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        createIndex("traffic");

        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater_tabs"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of("traffic", Set.of("burp.repeater.tab_name", "burp.repeater.tab_group", "meta.schema_version")));

        Map<String, Object> built = objectMap(callStatic(
                RepeaterTabsIndexReporter.class,
                "buildDocument",
                repeaterRequestResponse(),
                "Tab-42",
                "Group-B"));

        PreparedExportDocument prepared = pushOneDocument("traffic", built, state);
        Map<String, Object> stored = awaitDocumentByExportId("traffic", prepared.exportId());

        assertThat(stored).containsKeys("meta", "burp");
        assertThat(stored).doesNotContainKeys("request", "response", "websocket");
        Map<?, ?> repeater = nestedMap(nestedMap(stored, "burp"), "repeater");
        assertThat(repeater.get("tab_name")).isEqualTo("Tab-42");
        assertThat(repeater.get("tab_group")).isEqualTo("Group-B");
        assertThat(nestedMap(stored, "burp").containsKey("reporting_tool")).isFalse();
    }

    private static HttpRequestResponse repeaterRequestResponse() {
        HttpRequest request = mock(HttpRequest.class);
        HttpResponse response = mock(HttpResponse.class);
        HttpService service = mock(HttpService.class);
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        ByteArray requestBytes = mock(ByteArray.class);
        ByteArray responseBytes = mock(ByteArray.class);
        when(requestResponse.request()).thenReturn(request);
        when(requestResponse.response()).thenReturn(response);
        when(requestResponse.httpService()).thenReturn(service);
        when(requestResponse.annotations()).thenReturn(null);

        when(service.host()).thenReturn("example.test");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(request.url()).thenReturn("https://example.test/repeat");
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/repeat");
        when(request.pathWithoutQuery()).thenReturn("/repeat");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.bodyOffset()).thenReturn(0);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);
        when(requestBytes.getBytes()).thenReturn(
                "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        when(request.toByteArray()).thenReturn(requestBytes);

        when(response.statusCode()).thenReturn((short) 200);
        when(response.reasonPhrase()).thenReturn("OK");
        when(response.httpVersion()).thenReturn("HTTP/1.1");
        when(response.headers()).thenReturn(List.of());
        when(response.cookies()).thenReturn(List.of());
        when(response.mimeType()).thenReturn(null);
        when(response.body()).thenReturn(null);
        when(response.bodyOffset()).thenReturn(0);
        when(response.markers()).thenReturn(List.of());
        when(responseBytes.getBytes()).thenReturn(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        when(response.toByteArray()).thenReturn(responseBytes);

        return requestResponse;
    }

    private static Map<String, Object> objectMap(Object value) {
        if (!(value instanceof Map<?, ?> source)) {
            return Map.of();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() instanceof String key) {
                out.put(key, entry.getValue());
            }
        }
        return out;
    }
}
