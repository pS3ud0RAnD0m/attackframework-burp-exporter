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
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

class ExporterIndexStatsReporterTest {

    private final ConfigState.State previousState = RuntimeConfig.getState();

    private void tearDown() {
        ExporterIndexStatsReporter.stop();
        RuntimeConfig.updateState(previousState);
        RuntimeConfig.setExportRunning(false);
        FileExportService.resetForTests();
    }

    @Test
    void pushSnapshotNow_writesExporterStats_whenExporterStatsEnabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("exporter-stats-file-only");
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
            ExportStats.recordRepeaterMetadataSource("request_identity");

            ExporterIndexStatsReporter.pushSnapshotNow();

            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("tool") + ".jsonl");
            assertThat(jsonlPath).exists();
            assertThat(Files.readString(jsonlPath)).contains("stats_snapshot");
            assertThat(Files.readString(jsonlPath)).contains("repeater_live_metadata_source_summary");
        } finally {
            tearDown();
        }
    }

    @Test
    void pushSnapshotNow_skipsWrite_whenExporterStatsDisabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("exporter-stats-disabled");
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

            ExporterIndexStatsReporter.pushSnapshotNow();

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

            ExporterIndexStatsReporter.refreshScheduleForCurrentState();

            ScheduledExecutorService firstScheduler = getStatic(ExporterIndexStatsReporter.class, "scheduler");
            assertThat(firstScheduler).isNotNull();
            assertThat((Integer) getStatic(ExporterIndexStatsReporter.class, "scheduledIntervalSeconds")).isEqualTo(30);

            RuntimeConfig.updateState(stateWithInterval(45));
            ExporterIndexStatsReporter.refreshScheduleForCurrentState();

            ScheduledExecutorService secondScheduler = getStatic(ExporterIndexStatsReporter.class, "scheduler");
            assertThat(secondScheduler).isNotNull();
            assertThat(secondScheduler).isNotSameAs(firstScheduler);
            assertThat((Integer) getStatic(ExporterIndexStatsReporter.class, "scheduledIntervalSeconds")).isEqualTo(45);
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
