package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.config.ConfigState;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigControllerOpenSearchErrorIT {

    private static final int TIMEOUT_SECONDS = 4;

    @Test
    void malformedUrl_reportsError_for_testConnection_and_createIndexes() throws Exception {
        CapturingUi ui = new CapturingUi();
        ConfigController c = new ConfigController(ui);

        String badUrl = "http://127.0.0.1:1/::::bad";

        // testConnectionAsync: "Testing ..." then final "✖ ..." line
        ui.resetOsLatchTwo();
        c.testConnectionAsync(badUrl);
        assertThat(ui.awaitOs()).isTrue();
        assertThat(ui.lastOsStatus).matches("(?s)^✖ .*");

        // createIndexesAsync may summarize directly as "Indexes failed: ..." or emit "✖ ..."
        ui.resetOsLatchTwo();
        c.createIndexesAsync(badUrl, List.of("settings"));
        assertThat(ui.awaitOs()).isTrue();
        assertThat(ui.lastOsStatus).matches("(?s)^✖ .*|.*Indexes failed:.*");
    }

    private static final class CapturingUi implements ConfigController.Ui {
        volatile String lastFileStatus = "";
        volatile String lastOsStatus = "";
        volatile String lastAdminStatus = "";
        volatile ConfigState.State lastImported;

        private CountDownLatch osLatch = new CountDownLatch(1);

        void resetOsLatchTwo() { osLatch = new CountDownLatch(2); }
        boolean awaitOs() throws InterruptedException { return osLatch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS); }

        @Override public void onFileStatus(String message) { lastFileStatus = message == null ? "" : message; }
        @Override public void onOpenSearchStatus(String message) { lastOsStatus = message == null ? "" : message; osLatch.countDown(); }
        @Override public void onAdminStatus(String message) { lastAdminStatus = message == null ? "" : message; }
        @Override public void onImportResult(ConfigState.State state) { lastImported = state; }
    }
}
