package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

class ToolIndexLogForwarderTest {

    @Test
    void onLog_noops_beforeStart_and_doesNotQueueWork() {
        ToolIndexLogForwarder forwarder = new ToolIndexLogForwarder();
        try {
            RuntimeConfig.setExportRunning(false);

            forwarder.onLog("INFO", "pre-start log");
        } finally {
            forwarder.stop();
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void onLog_noops_duringStartupBootstrap_and_doesNotQueueWork() {
        ToolIndexLogForwarder forwarder = new ToolIndexLogForwarder();
        try {
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(true);

            forwarder.onLog("INFO", "startup log");
        } finally {
            forwarder.stop();
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void onLog_writesToolLog_whenOnlyFileExportIsEnabled_andSavedOpenSearchUrlExists() throws Exception {
        ToolIndexLogForwarder forwarder = null;
        try {
            Path root = TestPathSupport.createDirectory("tool-log-file-only");
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(true, root.toString(), false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);
            long openSearchToolSuccessBefore = ExportStats.getSuccessCount("tool");
            forwarder = new ToolIndexLogForwarder();

            forwarder.onLog("INFO", "file-only log");

            Path ndjsonPath = root.resolve(IndexNaming.indexNameForShortName("tool") + ".ndjson");
            Thread.sleep(250L);
            assertThat(ndjsonPath).exists();
            assertThat(Files.readString(ndjsonPath)).contains("file-only log");
            assertThat(ExportStats.getSuccessCount("tool")).isEqualTo(openSearchToolSuccessBefore);
        } finally {
            if (forwarder != null) {
                forwarder.stop();
            }
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }
}
