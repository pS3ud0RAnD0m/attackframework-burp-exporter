package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.nestedMap;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.pushOneDocument;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.stringObjectMapList;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.awaitSingleIndexedDocument;
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

import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class TrafficParamIntegrityExportOpenSearchIT {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    public void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        deleteIndex("traffic");
    }

    @Test
    void gzipUrlencodedForm_indexesSupplementalBodyParamsWithoutExportMetadata() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        byte[] plain = "org_id=abc&sid=xyz".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] gzip = gzipBytes(plain);
        ParsedHttpParameter garbageBody = mock(ParsedHttpParameter.class);
        when(garbageBody.name()).thenReturn("\u001f\u008b");
        when(garbageBody.value()).thenReturn("");
        when(garbageBody.type()).thenReturn(HttpParameterType.BODY);
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(List.of(garbageBody));
        when(request.method()).thenReturn("POST");
        when(request.url()).thenReturn("https://example.test/param-integrity-it");
        when(request.path()).thenReturn("/param-integrity-it");
        when(request.pathWithoutQuery()).thenReturn("/param-integrity-it");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.contentType()).thenReturn(ContentType.URL_ENCODED);
        HttpHeader contentType = mock(HttpHeader.class);
        when(contentType.name()).thenReturn("Content-Type");
        when(contentType.value()).thenReturn("application/x-www-form-urlencoded");
        HttpHeader encoding = mock(HttpHeader.class);
        when(encoding.name()).thenReturn("Content-Encoding");
        when(encoding.value()).thenReturn("gzip");
        when(request.headers()).thenReturn(List.of(contentType, encoding));
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn(gzip);
        when(request.body()).thenReturn(body);
        when(request.markers()).thenReturn(List.of());

        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
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

        assertThat(nestedMap(stored, "meta").containsKey("export")).isFalse();

        List<Map<String, Object>> parameters = stringObjectMapList(nestedMap(stored, "request").get("parameters"));
        assertThat(parameters).extracting(p -> p.get("name")).contains("org_id", "sid");
        assertThat(parameters).extracting(p -> p.get("type")).containsOnly("BODY");
    }

    private static byte[] gzipBytes(byte[] input) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try (java.util.zip.GZIPOutputStream gzip = new java.util.zip.GZIPOutputStream(out)) {
            gzip.write(input);
        }
        return out.toByteArray();
    }
}
