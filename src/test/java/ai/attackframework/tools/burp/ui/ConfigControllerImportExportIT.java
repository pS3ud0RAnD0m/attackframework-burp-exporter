package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigControllerImportExportIT {

    private static final class TestUi implements ConfigController.Ui {
        volatile String admin;
        volatile ConfigState.State lastImported;
        @Override public void onFileStatus(String message) { /* not used */ }
        @Override public void onOpenSearchStatus(String message) { /* not used */ }
        @Override public void onAdminStatus(String message) { this.admin = message; }
    }

    @Test
    void export_then_import_roundtrip_emitsStatus() throws Exception {
        // Build a small state
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, false, null));

        String json = ConfigJsonMapper.build(state);
        Path tmp = Files.createTempFile("cc-export", ".json");
        tmp.toFile().deleteOnExit();

        TestUi ui = new TestUi();
        ConfigController cc = new ConfigController(ui);

        CountDownLatch exportDone = new CountDownLatch(1);
        new Thread(() -> {
            while (ui.admin == null || !ui.admin.startsWith("Export")) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) { }
            }
            exportDone.countDown();
        }).start();

        cc.exportConfigAsync(tmp, json);
        assertThat(exportDone.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.admin).contains("Exported");

        CountDownLatch importDone = new CountDownLatch(1);
        ui.admin = null;
        new Thread(() -> {
            while (ui.admin == null || !ui.admin.startsWith("Imported")) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) { }
            }
            importDone.countDown();
        }).start();

        cc.importConfigAsync(tmp);
        assertThat(importDone.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.admin).contains("Imported");
    }
}
