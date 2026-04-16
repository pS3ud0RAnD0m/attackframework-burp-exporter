package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.getStatic;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

class ToolIndexStatsReporterTest {

    private final ConfigState.State previousState = RuntimeConfig.getState();

    private void tearDown() {
        ToolIndexStatsReporter.stop();
        RuntimeConfig.updateState(previousState);
        RuntimeConfig.setExportRunning(false);
        FileExportService.resetForTests();
    }

    @Test
    void pushSnapshotNow_writesToolStats_whenExporterStatsEnabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("tool-stats-file-only");
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, root.toString(), true, false,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            ToolIndexStatsReporter.pushSnapshotNow();

            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("tool") + ".jsonl");
            assertThat(jsonlPath).exists();
            assertThat(Files.readString(jsonlPath)).contains("stats_snapshot");
        } finally {
            tearDown();
        }
    }

    @Test
    void pushSnapshotNow_skipsWrite_whenExporterStatsDisabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("tool-stats-disabled");
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, root.toString(), true, false,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    List.of(ConfigKeys.SRC_EXPORTER_INFO, ConfigKeys.SRC_EXPORTER_CONFIG),
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            ToolIndexStatsReporter.pushSnapshotNow();

            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("tool") + ".jsonl");
            assertThat(jsonlPath).doesNotExist();
        } finally {
            tearDown();
        }
    }

    @Test
    void refreshScheduleForCurrentState_recreatesScheduler_whenIntervalChanges() {
        try {
            RuntimeConfig.updateState(stateWithInterval(30));
            RuntimeConfig.setExportRunning(true);

            ToolIndexStatsReporter.refreshScheduleForCurrentState();

            ScheduledExecutorService firstScheduler = getStatic(ToolIndexStatsReporter.class, "scheduler");
            assertThat(firstScheduler).isNotNull();
            assertThat((Integer) getStatic(ToolIndexStatsReporter.class, "scheduledIntervalSeconds")).isEqualTo(30);

            RuntimeConfig.updateState(stateWithInterval(45));
            ToolIndexStatsReporter.refreshScheduleForCurrentState();

            ScheduledExecutorService secondScheduler = getStatic(ToolIndexStatsReporter.class, "scheduler");
            assertThat(secondScheduler).isNotNull();
            assertThat(secondScheduler).isNotSameAs(firstScheduler);
            assertThat((Integer) getStatic(ToolIndexStatsReporter.class, "scheduledIntervalSeconds")).isEqualTo(45);
        } finally {
            tearDown();
        }
    }

    private static ConfigState.State stateWithInterval(int intervalSeconds) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_EXPORTER),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, false,
                        false, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                intervalSeconds,
                null);
    }
}
