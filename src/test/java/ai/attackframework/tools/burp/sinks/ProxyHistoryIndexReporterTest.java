package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Unit tests for {@link ProxyHistoryIndexReporter}: no-op paths when PROXY_HISTORY
 * is not selected or export is not running (no OpenSearch or MontoyaApi required).
 */
class ProxyHistoryIndexReporterTest {

    @AfterEach
    @SuppressWarnings("unused")
    void resetRuntimeConfig() {
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
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("PROXY", "REPEATER"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        ));
        assertThatCode(() -> ProxyHistoryIndexReporter.pushSnapshotNow()).doesNotThrowAnyException();
    }

    @Test
    void pushSnapshotNow_doesNotThrow_whenExportNotRunning() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("PROXY_HISTORY"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        ));
        assertThatCode(() -> ProxyHistoryIndexReporter.pushSnapshotNow()).doesNotThrowAnyException();
    }

    @Test
    void pushSnapshotNow_returnsImmediately_withoutBlocking() throws InterruptedException {
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("PROXY_HISTORY"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        ));
        long start = System.currentTimeMillis();
        ProxyHistoryIndexReporter.pushSnapshotNow();
        long elapsed = System.currentTimeMillis() - start;
        assertThat(elapsed).isLessThan(500);
    }

    @Test
    void emptyResponseDoc_matchesCurrentTrafficResponseShape() {
        @SuppressWarnings("unchecked")
        Map<String, Object> responseDoc = (Map<String, Object>) callStatic(ProxyHistoryIndexReporter.class, "emptyResponseDoc");

        assertThat(responseDoc).containsKeys(
                "status", "status_code_class", "reason_phrase", "http_version", "headers", "cookies",
                "mime_type", "stated_mime_type", "inferred_mime_type", "body", "markers");
        assertThat(responseDoc).doesNotContainKeys("header_names", "body_length", "body_offset");

        @SuppressWarnings("unchecked")
        Map<String, Object> headers = (Map<String, Object>) responseDoc.get("headers");
        assertThat(headers).containsKeys("full", "names", "etag", "last_modified", "content_location");
        assertThat(headers.get("full")).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class)).isEmpty();
        assertThat(headers.get("names")).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class)).isEmpty();

        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) responseDoc.get("body");
        assertThat(body).containsEntry("length", 0).containsEntry("offset", 0).containsEntry("b64", null).containsEntry("text", null);
    }
}
