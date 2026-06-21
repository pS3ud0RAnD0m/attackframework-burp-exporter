package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.awaitSingleIndexedDocument;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.nestedMap;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.pushOneDocument;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Verifies mis-gate traffic documents index without per-doc export metadata at
 * {@link OpenSearchReachable#BASE_URL}.
 */
@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class TrafficMisgateExportOpenSearchIT {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        deleteIndex("traffic");
    }

    @Test
    void misgateSuspect_indexesRequestWithoutBodyParamsOrExportMetadata() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        byte[] bodyBytes = new byte[] {0x00, 0x01, 0x02, 0x03};
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(List.of());
        when(request.method()).thenReturn("POST");
        when(request.pathWithoutQuery()).thenReturn("/collect");
        when(request.path()).thenReturn("/collect");
        when(request.query()).thenReturn("");
        when(request.url()).thenReturn("https://app-measurement.com/a/collect");
        when(request.contentType()).thenReturn(ContentType.URL_ENCODED);
        HttpHeader contentTypeHeader = header("Content-Type", "application/x-www-form-urlencoded");
        when(request.headers()).thenReturn(List.of(contentTypeHeader));
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn(bodyBytes);
        when(request.body()).thenReturn(body);
        when(request.markers()).thenReturn(List.of());
        when(request.fileExtension()).thenReturn("");

        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> builtParameters =
                (List<Map<String, Object>>) requestDoc.get("parameters");
        assertThat(builtParameters).isEmpty();

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("request", requestDoc);
        doc.put("meta", ExportMetaFields.meta("it"));

        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of(),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);

        deleteIndex("traffic");
        createIndex("traffic");
        pushOneDocument("traffic", doc, state);
        Map<String, Object> stored = awaitSingleIndexedDocument("traffic");

        Map<?, ?> meta = nestedMap(stored, "meta");
        assertThat(meta.containsKey("export")).isFalse();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> parameters =
                (List<Map<String, Object>>) nestedMap(stored, "request").get("parameters");
        assertThat(parameters).isNullOrEmpty();
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn(name);
        when(h.value()).thenReturn(value);
        return h;
    }
}
