package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.config.ConfigState;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigControllerFilesIT {

    private static final int TIMEOUT_SECONDS = 4;

    @Test
    void createFilesAsync_creates_then_reportsAlreadyExisted_onSecondRun() throws Exception {
        Path tmp = Files.createTempDirectory("af-files-");
        CapturingUi ui = new CapturingUi();
        ConfigController c = new ConfigController(ui);

        ui.resetFileLatch();
        c.createFilesAsync(tmp.toString(), List.of("settings", "sitemap"));
        assertThat(ui.awaitFile()).as("first status").isTrue();
        // Accept singular/plural: "File(s) created:"
        assertThat(ui.lastFileStatus).matches("(?s)^(File|Files) created:.*");

        ui.resetFileLatch();
        c.createFilesAsync(tmp.toString(), List.of("settings", "sitemap"));
        assertThat(ui.awaitFile()).as("second status").isTrue();
        // Accept singular/plural: "File(s) already existed:"
        assertThat(ui.lastFileStatus).matches("(?s)^Files? already existed:.*");
    }

    @Test
    void createFilesAsync_reportsFailed_whenRootIsAFile() throws Exception {
        Path tmpFile = Files.createTempFile("af-files-", ".tmp");
        CapturingUi ui = new CapturingUi();
        ConfigController c = new ConfigController(ui);

        ui.resetFileLatch();
        c.createFilesAsync(tmpFile.toString(), List.of("settings"));
        assertThat(ui.awaitFile()).isTrue();
        // Accept singular/plural: "File creation(s) failed:"
        assertThat(ui.lastFileStatus).matches("(?s)^File creations? failed:.*");
    }

    private static final class CapturingUi implements ConfigController.Ui {
        volatile String lastFileStatus = "";
        volatile String lastOsStatus = "";
        volatile String lastAdminStatus = "";
        volatile ConfigState.State lastImported;

        private CountDownLatch fileLatch = new CountDownLatch(1);

        void resetFileLatch() { fileLatch = new CountDownLatch(1); }
        boolean awaitFile() throws InterruptedException { return fileLatch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS); }

        @Override public void onFileStatus(String message) {
            lastFileStatus = message == null ? "" : message;
            fileLatch.countDown();
        }
        @Override public void onOpenSearchStatus(String message) { lastOsStatus = message == null ? "" : message; }
        @Override public void onAdminStatus(String message) { lastAdminStatus = message == null ? "" : message; }
        @Override public void onImportResult(ConfigState.State state) { lastImported = state; }
    }
}
