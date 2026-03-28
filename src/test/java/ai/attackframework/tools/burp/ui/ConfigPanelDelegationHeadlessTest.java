package ai.attackframework.tools.burp.ui;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import javax.swing.JCheckBox;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.ui.controller.ConfigController;

/**
 * Verifies that the panel delegates to the controller and posts OpenSearch status updates.
 */
@SuppressWarnings("unused")
class ConfigPanelDelegationHeadlessTest {

    private static final class TestUi implements ConfigController.Ui {
        volatile String fileMsg;
        volatile String osMsg;
        @Override public void onFileStatus(String m) { fileMsg = m; }
        @Override public void onOpenSearchStatus(String m) { osMsg = m; }
        @Override public void onControlStatus(String m) {
            // Control status is not used in this scenario; required by ConfigController.Ui
        }
    }

    private TestUi ui;
    private ConfigPanel panel;
    private Path defaultFileRoot;

    @BeforeEach
    void setup() throws Exception {
        ui = new TestUi();
        defaultFileRoot = TestPathSupport.defaultUiFileRoot();
        Assumptions.assumeTrue(TestPathSupport.isWritableDirectory(defaultFileRoot),
                "Default UI file root is not writable: " + defaultFileRoot);
        TestPathSupport.cleanupExportArtifacts(defaultFileRoot);
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel p = new ConfigPanel(new ConfigController(ui));
            if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                p.setSize(1000, 700);
            }
            p.doLayout();

            // Enable OpenSearch and Files destinations so OS and Files buttons are actionable
            JCheckBox osEnable = get(p, "openSearchSinkCheckbox");
            if (!osEnable.isSelected()) osEnable.doClick();
            JCheckBox filesEnable = get(p, "fileSinkCheckbox");
            if (!filesEnable.isSelected()) filesEnable.doClick();
            JRadioButton bulkNdjsonEnable = get(p, "fileBulkNdjsonCheckbox");
            if (!bulkNdjsonEnable.isSelected()) bulkNdjsonEnable.doClick();
            JTextField filePathField = get(p, "filePathField");
            filePathField.setText(defaultFileRoot.toString());

            ref.set(p);
        });
        panel = ref.get();
    }

    @AfterEach
    void cleanupDefaultRoot() throws IOException {
        TestPathSupport.cleanupExportArtifacts(defaultFileRoot);
    }

    @Test
    void clicking_testConnection_invokes_controller_and_posts_status() throws Exception {
        javax.swing.JButton testConn = get(panel, "testConnectionButton");

        onEdtAndWait(() -> {
            testConn.doClick();
        });

        await(() -> ui.osMsg != null);

        assertThat(ui.osMsg).isNotBlank();
    }

    // ---- helpers ----
    private static void onEdtAndWait(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }

    private static void await(java.util.concurrent.Callable<Boolean> cond) {
        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline) {
            try {
                if (Boolean.TRUE.equals(cond.call())) {
                    return;
                }
            } catch (Exception ignored) {
                // Condition evaluation failed; continue until deadline or success.
            }
            LockSupport.parkNanos(15_000_000L); // ~15ms without using Thread.sleep
        }
    }
}
