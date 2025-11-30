package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pressing Enter in the OS URL field should invoke testConnection.
 * Ensures OpenSearch is enabled before firing the action.
 */
class ConfigPanelEnterBindingsHeadlessTest {

    private static final class TestUi implements ConfigController.Ui {
        final AtomicReference<String> os = new AtomicReference<>();
        @Override public void onFileStatus(String m) { }
        @Override public void onOpenSearchStatus(String m) { os.set(m); }
        @Override public void onAdminStatus(String m) { }
    }

    private TestUi ui;
    private ConfigPanel panel;

    @BeforeEach
    void setup() {
        ui = new TestUi();
        panel = new ConfigPanel(new ConfigController(ui));
        JCheckBox osEnable = (JCheckBox) findByName(panel, "os.enable");
        if (osEnable != null && !osEnable.isSelected()) osEnable.doClick();
    }

    @Test
    void pressEnterOnOpenSearchUrlField_triggersTestConnection_andUpdatesStatus() {
        JTextField field = (JTextField) findByName(panel, "os.url");
        if (field == null) throw new IllegalStateException("Component not found: os.url");

        field.setText("http://127.0.0.1:1");
        field.postActionEvent(); // Enter -> bound action triggers testConnection

        await(() -> ui.os.get() != null);
        assertThat(ui.os.get()).isNotBlank();
    }

    // ---- helpers ----
    private static Component findByName(Container root, String name) {
        if (name != null && name.equals(root.getName())) return root;
        for (Component c : root.getComponents()) {
            if (name != null && name.equals(c.getName())) return c;
            if (c instanceof Container child) {
                Component hit = findByName(child, name);
                if (hit != null) return hit;
            }
        }
        return null;
    }

    private static void await(java.util.concurrent.Callable<Boolean> cond) {
        long deadline = System.currentTimeMillis() + 2500;
        while (System.currentTimeMillis() < deadline) {
            try { if (Boolean.TRUE.equals(cond.call())) return; } catch (Exception ignored) {}
            try { Thread.sleep(15); } catch (InterruptedException ignored) {}
        }
        throw new AssertionError("Timed out waiting for OpenSearch status");
    }
}
