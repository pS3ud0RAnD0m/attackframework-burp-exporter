package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

class ExporterIndexConfigReporterFileExportTest {

    private final ConfigState.State previous = RuntimeConfig.getState();

    private void tearDown() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        FileExportService.resetForTests();
    }

    @Test
    void pushConfigSnapshot_writesExporterDocument_whenOnlyFileExportIsEnabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("exporter-config-file-only");
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, root.toString(), true, true,
                            true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                            true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);
            long openSearchExporterSuccessBefore = ExportStats.getSuccessCount("exporter");

            ExporterIndexConfigReporter.pushConfigSnapshot();

            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("exporter") + ".jsonl");
            Path ndjsonPath = root.resolve(IndexNaming.indexNameForShortName("exporter") + ".ndjson");
            assertThat(jsonlPath).exists();
            assertThat(ndjsonPath).exists();
            assertThat(Files.readString(jsonlPath)).contains("config_snapshot");
            assertThat(ExportStats.getSuccessCount("exporter")).isEqualTo(openSearchExporterSuccessBefore);
        } finally {
            tearDown();
        }
    }

    @Test
    void pushConfigSnapshot_doesNotWriteExporterDocument_whenExporterSourceDisabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("exporter-config-disabled");
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, root.toString(), true, true,
                            true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                            true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            ExporterIndexConfigReporter.pushConfigSnapshot();

            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("exporter") + ".jsonl");
            Path ndjsonPath = root.resolve(IndexNaming.indexNameForShortName("exporter") + ".ndjson");
            assertThat(jsonlPath).doesNotExist();
            assertThat(ndjsonPath).doesNotExist();
        } finally {
            tearDown();
        }
    }

    @Test
    void buildConfigDoc_includesExporterOptionsAndStatsInterval() {
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_EXPORTER),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, false,
                        false, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                List.of("high"),
                List.of(ConfigKeys.SRC_EXPORTER_INFO, ConfigKeys.SRC_EXPORTER_STATS),
                45,
                null);

        Map<?, ?> doc = (Map<?, ?>) callStatic(ExporterIndexConfigReporter.class, "buildConfigDoc", state);
        Map<?, ?> event = nestedMap(doc, "event");
        Map<?, ?> data = nestedMap(event, "data");
        Map<?, ?> options = nestedMap(data, "data_source_options");

        assertThat(event.get("type")).isEqualTo("config_snapshot");
        assertThat(event.get("level")).isEqualTo("INFO");
        assertThat(event.get("source")).isEqualTo("burp-exporter");
        assertThat(event.get("thread")).isInstanceOf(String.class);
        assertThat(doc.containsKey("event_type")).isFalse();
        assertThat(doc.containsKey("level")).isFalse();
        assertThat(doc.containsKey("source")).isFalse();
        assertThat(doc.containsKey("thread")).isFalse();
        assertThat(doc.containsKey("extension_version")).isFalse();
        assertThat(doc.containsKey("message")).isFalse();
        assertThat(doc.containsKey("message_text")).isFalse();
        assertThat(doc.containsKey("burp")).isFalse();
        assertThat(doc.containsKey("burp_version")).isFalse();
        assertThat(doc.containsKey("project_id")).isFalse();
        assertThat(event.get("summary")).isEqualTo("config_snapshot scope=all sources=2 exporter=true");
        assertThat(options.get("exporter")).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class))
                .containsExactly(ConfigKeys.SRC_EXPORTER_INFO, ConfigKeys.SRC_EXPORTER_STATS);
        assertThat(options.get("exporter_stats_interval_seconds")).isEqualTo(45);
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }
}
