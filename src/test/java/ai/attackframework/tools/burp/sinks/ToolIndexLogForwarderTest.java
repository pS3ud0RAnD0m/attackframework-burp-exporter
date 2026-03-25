package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.BlockingQueue;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
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
}
