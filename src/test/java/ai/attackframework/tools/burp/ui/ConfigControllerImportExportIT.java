package ai.attackframework.tools.burp.ui;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;

class ConfigControllerImportExportIT {

    private static final class TestUi implements ConfigController.Ui {
        volatile String admin;
        private CountDownLatch exportDone;
        private CountDownLatch importDone;

        void setExportLatch(CountDownLatch latch) {
            this.exportDone = latch;
        }

        void setImportLatch(CountDownLatch latch) {
            this.importDone = latch;
        }

        @Override public void onFileStatus(String message) { /* not used */ }
        @Override public void onOpenSearchStatus(String message) { /* not used */ }
        @Override public void onAdminStatus(String message) {
            this.admin = message;
            if (message == null) {
                return;
            }

            CountDownLatch exp = exportDone;
            if (exp != null && message.startsWith("Export")) {
                exp.countDown();
            }

            CountDownLatch imp = importDone;
            if (imp != null && message.startsWith("Imported")) {
                imp.countDown();
            }
        }
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
        ui.setExportLatch(exportDone);

        cc.exportConfigAsync(tmp, json);
        assertThat(exportDone.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.admin).contains("Exported");

        CountDownLatch importDone = new CountDownLatch(1);
        ui.admin = null;
        ui.setImportLatch(importDone);

        cc.importConfigAsync(tmp);
        assertThat(importDone.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.admin).contains("Imported");
    }
}
