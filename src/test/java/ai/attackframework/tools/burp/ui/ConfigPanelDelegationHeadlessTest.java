package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicReference;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the panel delegates to the controller and posts Ui updates.
 * Enables OpenSearch (os.enable) before invoking OS actions.
 */
class ConfigPanelDelegationHeadlessTest {

    private static final class TestUi implements ConfigController.Ui {
        volatile String fileMsg;
        volatile String osMsg;
        @Override public void onFileStatus(String m) { fileMsg = m; }
        @Override public void onOpenSearchStatus(String m) { osMsg = m; }
        @Override public void onAdminStatus(String m) { }
    }

    private TestUi ui;
    private ConfigPanel panel;

    @BeforeEach
    void setup() throws Exception {
        ui = new TestUi();
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel p = new ConfigPanel(new ConfigController(ui));
            if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                p.setSize(1000, 700);
            }
            p.doLayout();

            // Enable OpenSearch sink so OS buttons are actionable
            JCheckBox osEnable = get(p, "openSearchSinkCheckbox");
            if (!osEnable.isSelected()) osEnable.doClick();

            ref.set(p);
        });
        panel = ref.get();
    }

    @Test
    void clicking_buttons_invokes_controller_and_posts_status() throws Exception {
        JButton testConn  = get(panel, "testConnectionButton");
        JButton createIdx = get(panel, "createIndexesButton");
        JButton createFil = get(panel, "createFilesButton");

        onEdtAndWait(() -> {
            testConn.doClick();
            createIdx.doClick();
            createFil.doClick();
        });

        await(() -> ui.osMsg != null);
        await(() -> ui.fileMsg != null);

        assertThat(ui.osMsg).isNotBlank();
        assertThat(ui.fileMsg).isNotBlank();
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
        long deadline = System.currentTimeMillis() + 2500;
        while (System.currentTimeMillis() < deadline) {
            try { if (Boolean.TRUE.equals(cond.call())) return; } catch (Exception ignored) {}
            try { Thread.sleep(15); } catch (InterruptedException ignored) {}
        }
    }
}
