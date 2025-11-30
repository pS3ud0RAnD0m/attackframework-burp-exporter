package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigControllerOpenSearchReasonIT {

    private static final class TestUi implements ConfigController.Ui {
        volatile String osMsg;
        @Override public void onFileStatus(String message) { /* not used */ }
        @Override public void onOpenSearchStatus(String message) { this.osMsg = message; }
        @Override public void onAdminStatus(String message) { /* not used */ }
    }

    @Test
    void createIndexes_failure_containsReason_whenAvailable() throws Exception {
        TestUi ui = new TestUi();
        ConfigController cc = new ConfigController(ui);

        CountDownLatch done = new CountDownLatch(1);
        new Thread(() -> {
            while (ui.osMsg == null) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) { }
            }
            done.countDown();
        }).start();

        // Using an unreachable endpoint should produce a failure summary with a reason
        cc.createIndexesAsync("http://127.0.0.1:1", List.of("settings"));
        assertThat(done.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.osMsg).containsAnyOf("failed", "interrupted", "Test failed");
    }
}
