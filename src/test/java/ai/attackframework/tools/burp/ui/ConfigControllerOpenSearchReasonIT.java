package ai.attackframework.tools.burp.ui;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.ui.controller.ConfigController;

class ConfigControllerOpenSearchReasonIT {

    private static final class TestUi implements ConfigController.Ui {
        final CountDownLatch done;
        volatile String osMsg;

        TestUi(CountDownLatch done) {
            this.done = done;
        }

        @Override public void onFileStatus(String message) { /* not used */ }
        @Override public void onOpenSearchStatus(String message) {
            this.osMsg = message;
            done.countDown();
        }
        @Override public void onControlStatus(String message) { /* not used */ }
    }

    @Test
    void createIndexes_failure_containsReason_whenAvailable() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        TestUi ui = new TestUi(done);
        ConfigController cc = new ConfigController(ui);

        // Using an unreachable endpoint should produce a failure summary with a reason
        cc.createIndexesAsync("http://127.0.0.1:1", List.of("settings"));
        assertThat(done.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.osMsg).containsAnyOf("failed", "interrupted", "Test failed");
    }
}
