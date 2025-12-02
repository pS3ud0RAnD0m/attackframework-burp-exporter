package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigControllerOpenSearchErrorIT {

    private static final class TestUi implements ConfigController.Ui {
        final CountDownLatch done;
        volatile String osMsg;
        volatile String admin;

        TestUi(CountDownLatch done) {
            this.done = done;
        }

        @Override public void onFileStatus(String message) { /* not used */ }
        @Override public void onOpenSearchStatus(String message) {
            this.osMsg = message;
            done.countDown();
        }
        @Override public void onAdminStatus(String message) { this.admin = message; }
    }

    @Test
    void testConnection_withInvalidUrl_reportsFailure() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        TestUi ui = new TestUi(done);
        ConfigController cc = new ConfigController(ui);

        cc.testConnectionAsync("http://127.0.0.1:1"); // expected to fail quickly
        assertThat(done.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.osMsg).startsWith("Test failed").isNotEmpty();
    }

    @Test
    void createIndexes_withInvalidUrl_reportsFailure() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        TestUi ui = new TestUi(done);
        ConfigController cc = new ConfigController(ui);

        cc.createIndexesAsync("http://127.0.0.1:1", List.of("settings"));
        assertThat(done.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.osMsg).isNotBlank();
    }
}
