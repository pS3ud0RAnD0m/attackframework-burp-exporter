package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

class ToolIndexConfigReporterFileExportTest {

    private final ConfigState.State previous = RuntimeConfig.getState();

    private void tearDown() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        FileExportService.resetForTests();
    }

    @Test
    void pushConfigSnapshot_writesToolDocument_whenOnlyFileExportIsEnabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("tool-config-file-only");
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, root.toString(), true, true,
                            true, ConfigState.DEFAULT_FILE_TOTAL_CAP_BYTES,
                            true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            RuntimeConfig.setExportRunning(true);
            long openSearchToolSuccessBefore = ExportStats.getSuccessCount("tool");

            ToolIndexConfigReporter.pushConfigSnapshot();

            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("tool") + ".jsonl");
            Path ndjsonPath = root.resolve(IndexNaming.indexNameForShortName("tool") + ".ndjson");
            assertThat(jsonlPath).exists();
            assertThat(ndjsonPath).exists();
            assertThat(Files.readString(jsonlPath)).contains("config_snapshot");
            assertThat(ExportStats.getSuccessCount("tool")).isEqualTo(openSearchToolSuccessBefore);
        } finally {
            tearDown();
        }
    }
}
