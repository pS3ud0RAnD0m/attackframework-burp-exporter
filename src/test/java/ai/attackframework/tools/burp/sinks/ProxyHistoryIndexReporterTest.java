package ai.attackframework.tools.burp.sinks;

import java.util.List;

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
}
