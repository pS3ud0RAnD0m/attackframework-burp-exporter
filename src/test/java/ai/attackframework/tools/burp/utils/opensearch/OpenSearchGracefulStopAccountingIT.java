package ai.attackframework.tools.burp.utils.opensearch;

import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.baseUrl;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import ai.attackframework.tools.burp.sinks.BulkOutcomeRecorder;
import ai.attackframework.tools.burp.sinks.SingleDocOutcomeRecorder;
import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.testutils.Reflect;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Integration test: Stop does not increment OpenSearch failure stats for cancelled pushes.
 */
@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class OpenSearchGracefulStopAccountingIT {

    private final ConfigState.State previous = RuntimeConfig.getState();
    private final List<LogEvent> events = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> events.add(new LogEvent(level, message));

    @AfterEach
    void cleanup() {
        Logger.unregisterListener(listener);
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        ExportStats.resetForTests();
        deleteIndex("traffic");
    }

    @Test
    void stopDuringOpenSearchWork_doesNotIncrementFailureStats_andLogsCancelledPush() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        Logger.registerListener(listener);
        ExportStats.resetForTests();
        createIndex("traffic");

        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(false);

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("meta", Map.of("schema_version", "1"));
        doc.put("burp", Map.of("reporting_tool", "IT"));
        String indexName = IndexNaming.indexNameForShortName("traffic");

        int pushed = OpenSearchClientWrapper.pushBulk(baseUrl(), indexName, "traffic", List.of(doc));
        assertThat(pushed).isEqualTo(1);
        assertThat(ExportStats.getSuccessCount("traffic")).isZero();

        RuntimeConfig.setExportRunning(false);

        Reflect.callStatic(
                OpenSearchClientWrapper.class,
                "logPushOutcome",
                indexName,
                "doPushBulk",
                new IOException("Connection is closed"));

        SingleDocOutcomeRecorder.record("traffic", false, true, "push failed after stop");
        BulkOutcomeRecorder.record("traffic", "Traffic", "Bulk push", 3, 0, true);

        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getLastError("traffic")).isNull();
        assertThat(events).anySatisfy(e -> assertThat(e.message())
                .contains("[OpenSearch]")
                .contains("doPushBulk cancelled")
                .contains("export stopped"));
    }

    private record LogEvent(String level, String message) {
        LogEvent {
            level = level == null ? "" : level;
            message = message == null ? "" : message;
        }
    }
}
