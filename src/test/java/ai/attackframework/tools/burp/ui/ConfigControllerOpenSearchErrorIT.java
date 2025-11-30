package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigControllerOpenSearchErrorIT {

    private static final class TestUi implements ConfigController.Ui {
        volatile String osMsg;
        volatile String admin;
        @Override public void onFileStatus(String message) { /* not used */ }
        @Override public void onOpenSearchStatus(String message) { this.osMsg = message; }
        @Override public void onAdminStatus(String message) { this.admin = message; }
    }

    @Test
    void testConnection_withInvalidUrl_reportsFailure() throws Exception {
        TestUi ui = new TestUi();
        ConfigController cc = new ConfigController(ui);

        CountDownLatch done = new CountDownLatch(1);
        new Thread(() -> {
            while (ui.osMsg == null) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) { }
            }
            done.countDown();
        }).start();

        cc.testConnectionAsync("http://127.0.0.1:1"); // expected to fail quickly
        assertThat(done.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.osMsg).startsWith("Test failed").isNotEmpty();
    }

    @Test
    void createIndexes_withInvalidUrl_reportsFailure() throws Exception {
        TestUi ui = new TestUi();
        ConfigController cc = new ConfigController(ui);

        CountDownLatch done = new CountDownLatch(1);
        new Thread(() -> {
            while (ui.osMsg == null) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) { }
            }
            done.countDown();
        }).start();

        cc.createIndexesAsync("http://127.0.0.1:1", List.of("settings"));
        assertThat(done.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.osMsg).isNotBlank();
    }
}
