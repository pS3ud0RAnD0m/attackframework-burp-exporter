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

class ExporterIndexLogForwarderTest {

    @Test
    void onLog_noops_beforeStart_and_doesNotQueueWork() {
        ExporterIndexLogForwarder forwarder = new ExporterIndexLogForwarder();
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
        ExporterIndexLogForwarder forwarder = new ExporterIndexLogForwarder();
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
    void onLog_writesExporterLog_whenOnlyFileExportIsEnabled_andSavedOpenSearchUrlExists() throws Exception {
        ExporterIndexLogForwarder forwarder = null;
        try {
            Path root = TestPathSupport.createDirectory("exporter-log-file-only");
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(true, root.toString(), false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null
            ));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);
            long openSearchToolSuccessBefore = ExportStats.getSuccessCount("tool");
            forwarder = new ExporterIndexLogForwarder();

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

    @Test
    void onLog_skipsFileWrite_whenExporterSourceDisabled() throws Exception {
        ExporterIndexLogForwarder forwarder = null;
        try {
            Path root = TestPathSupport.createDirectory("exporter-log-disabled");
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(true, root.toString(), false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null
            ));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);
            forwarder = new ExporterIndexLogForwarder();

            forwarder.onLog("INFO", "should not be exported");
            Thread.sleep(250L);

            Path ndjsonPath = root.resolve(IndexNaming.indexNameForShortName("tool") + ".ndjson");
            assertThat(ndjsonPath).doesNotExist();
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
