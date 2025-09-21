package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigControllerImportExportIT {

    private static final int TIMEOUT_SECONDS = 4;

    @Test
    void export_then_import_roundtrip_returns_matching_state() throws Exception {
        ConfigState.State state = new ConfigState.State(
                List.of("settings", "traffic"),
                "custom",
                List.of(new ConfigState.ScopeEntry("^foo$", ConfigState.Kind.REGEX)),
                new ConfigState.Sinks(true, "/tmp/af", true, "http://opensearch.url:9200")
        );
        String json = ConfigJsonMapper.build(state);

        Path dir = Files.createTempDirectory("af-export-");
        Path out = dir.resolve("cfg.json");

        CapturingUi ui = new CapturingUi();
        ConfigController c = new ConfigController(ui);

        ui.resetAdminLatch();
        c.exportConfigAsync(out, json);
        assertThat(ui.awaitAdmin()).isTrue();
        assertThat(Files.exists(out)).isTrue();
        assertThat(ui.lastAdminStatus).contains("Exported to ");

        ui.resetAdminLatch();
        ui.resetImport();
        c.importConfigAsync(out);
        assertThat(ui.awaitAdmin()).isTrue();
        assertThat(ui.lastImported).isNotNull();
        assertThat(ui.lastImported.scopeType()).isEqualTo("custom");
        assertThat(ui.lastImported.customEntries()).hasSize(1);
        assertThat(ui.lastImported.customEntries().getFirst().value()).isEqualTo("^foo$");
    }

    private static final class CapturingUi implements ConfigController.Ui {
        volatile String lastFileStatus = "";
        volatile String lastOsStatus = "";
        volatile String lastAdminStatus = "";
        volatile ConfigState.State lastImported;

        private CountDownLatch adminLatch = new CountDownLatch(1);

        void resetAdminLatch() { adminLatch = new CountDownLatch(1); }
        void resetImport() { lastImported = null; }
        boolean awaitAdmin() throws InterruptedException { return adminLatch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS); }

        @Override public void onFileStatus(String message) { lastFileStatus = message == null ? "" : message; }
        @Override public void onOpenSearchStatus(String message) { lastOsStatus = message == null ? "" : message; }
        @Override public void onAdminStatus(String message) { lastAdminStatus = message == null ? "" : message; adminLatch.countDown(); }
        @Override public void onImportResult(ConfigState.State state) { lastImported = state; }
    }
}
