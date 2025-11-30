package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigControllerFilesIT {

    private static final class TestUi implements ConfigController.Ui {
        volatile String fileMsg;
        @Override public void onFileStatus(String message) { this.fileMsg = message; }
        @Override public void onOpenSearchStatus(String message) { /* not used */ }
        @Override public void onAdminStatus(String message) { /* not used */ }
    }

    @Test
    void createFiles_writesExpectedStatus() throws Exception {
        Path tmp = Files.createTempDirectory("cc-files");
        tmp.toFile().deleteOnExit();

        TestUi ui = new TestUi();
        ConfigController cc = new ConfigController(ui);

        CountDownLatch done = new CountDownLatch(1);
        // wait for async UI message
        new Thread(() -> {
            while (ui.fileMsg == null) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) { }
            }
            done.countDown();
        }).start();

        cc.createFilesAsync(tmp.toString(), List.of(
                ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_SITEMAP));

        assertThat(done.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.fileMsg)
                .isNotBlank()
                .containsAnyOf("Created file", "Created files", "already existed");
    }
}
