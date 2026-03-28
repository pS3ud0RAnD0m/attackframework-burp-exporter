package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.BlockingQueue;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
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

            BlockingQueue<?> queue = get(forwarder, "queue");
            assertThat(queue).isEmpty();
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

            BlockingQueue<?> queue = get(forwarder, "queue");
            assertThat(queue).isEmpty();
        } finally {
            forwarder.stop();
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void onLog_noops_whenOnlyFileExportIsEnabled_andSavedOpenSearchUrlExists() {
        ToolIndexLogForwarder forwarder = new ToolIndexLogForwarder();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            RuntimeConfig.setExportRunning(true);

            forwarder.onLog("INFO", "file-only log");

            BlockingQueue<?> queue = get(forwarder, "queue");
            assertThat(queue).isEmpty();
        } finally {
            forwarder.stop();
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }
}
