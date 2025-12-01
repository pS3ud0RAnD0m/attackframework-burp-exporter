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
        final CountDownLatch done;
        volatile String fileMsg;

        TestUi(CountDownLatch done) {
            this.done = done;
        }

        @Override public void onFileStatus(String message) {
            this.fileMsg = message;
            done.countDown();
        }
        @Override public void onOpenSearchStatus(String message) { /* not used */ }
        @Override public void onAdminStatus(String message) { /* not used */ }
    }

    @Test
    void createFiles_writesExpectedStatus() throws Exception {
        Path tmp = Files.createTempDirectory("cc-files");
        tmp.toFile().deleteOnExit();

        CountDownLatch done = new CountDownLatch(1);
        TestUi ui = new TestUi(done);
        ConfigController cc = new ConfigController(ui);

        cc.createFilesAsync(tmp.toString(), List.of(
                ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_SITEMAP));

        assertThat(done.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.fileMsg)
                .isNotBlank()
                .containsAnyOf("Created file", "Created files", "already existed");
    }
}
