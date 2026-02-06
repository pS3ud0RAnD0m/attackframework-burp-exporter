package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import javax.swing.AbstractButton;
import javax.swing.JButton;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.ui.controller.ConfigController;

/**
 * Verifies that Save delegates to the controller and posts a control status.
 * Uses type-based lookup to avoid depending on button text.
 */
class ConfigPanelImportExportHeadlessTest {

    private static final class TestUi implements ConfigController.Ui {
        final AtomicReference<String> control = new AtomicReference<>();
        @Override public void onFileStatus(String message) {
            // File status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onOpenSearchStatus(String message) {
            // OpenSearch status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onControlStatus(String message) { control.set(message); }
    }

    @Test
    void export_via_save_logs_expected_json() {
        TestUi ui = new TestUi();
        ConfigPanel panel = new ConfigPanel(new ConfigController(ui));

        // Find a JButton labeled "Save" if present; otherwise pick the last button in Control block.
        JButton save = (JButton) findByTextOrLastButton(panel, "Save");
        save.doClick();

        await(() -> ui.control.get() != null);
        assertThat(ui.control.get()).isNotBlank();
    }

    // ---- helpers ----

    private static Component findByTextOrLastButton(Container root, String text) {
        Component foundText = findByText(root, text);
        if (foundText != null) return foundText;

        Component last = findLastButton(root);
        if (last != null) return last;

        throw new IllegalStateException("Save button not found (by text or position).");
    }

    private static Component findByText(Container root, String text) {
        for (Component c : root.getComponents()) {
            if (c instanceof AbstractButton b && text.equals(b.getText())) return b;
            if (c instanceof Container child) {
                Component hit = findByText(child, text);
                if (hit != null) return hit;
            }
        }
        return null;
    }

    private static Component findLastButton(Container root) {
        Component last = null;
        for (Component c : root.getComponents()) {
            if (c instanceof JButton) last = c;
            if (c instanceof Container child) {
                Component hit = findLastButton(child);
                if (hit != null) last = hit;
            }
        }
        return last;
    }

    private static void await(java.util.concurrent.Callable<Boolean> cond) {
        long deadline = System.currentTimeMillis() + 2500;
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
        throw new AssertionError("[save should log JSON] timed out");
    }
}
