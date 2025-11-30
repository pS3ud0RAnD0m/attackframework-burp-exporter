package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * OS test/create buttons should produce a Ui status update.
 * Ensures OpenSearch is enabled before invoking OS actions.
 */
class ConfigPanelHeadlessIT {

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
    void testConnection_button_completes_and_setsStatus() {
        JButton test = (JButton) find(panel, "os.test", "Test Connection");
        test.doClick();
        await(() -> ui.os.get() != null);
        assertThat(ui.os.get()).isNotBlank();
    }

    @Test
    void createIndexes_button_completes_and_setsStatus() {
        JButton idx = (JButton) find(panel, "os.createIndexes", "Create Indexes");
        idx.doClick();
        await(() -> ui.os.get() != null);
        assertThat(ui.os.get()).isNotBlank();
    }

    // ---- helpers ----
    private static Component find(Container root, String name, String text) {
        Component byName = findByName(root, name);
        if (byName != null) return byName;
        return findByText(root, text);
    }

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

    private static Component findByText(Container root, String text) {
        for (Component c : root.getComponents()) {
            if (c instanceof AbstractButton b && text.equals(b.getText())) return b;
            if (c instanceof Container child) {
                Component hit = findByText(child, text);
                if (hit != null) return hit;
            }
        }
        throw new IllegalStateException("Component not found: " + text);
    }

    private static void await(java.util.concurrent.Callable<Boolean> cond) {
        long deadline = System.currentTimeMillis() + 2500;
        while (System.currentTimeMillis() < deadline) {
            try { if (Boolean.TRUE.equals(cond.call())) return; } catch (Exception ignored) {}
            try { Thread.sleep(15); } catch (InterruptedException ignored) {}
        }
        throw new AssertionError("Timed out waiting for status text update; last value: \"\"");
    }
}
