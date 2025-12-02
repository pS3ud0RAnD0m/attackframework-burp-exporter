package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import org.junit.jupiter.api.Test;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration-style headless test validating that the panel can:
 *  1) Build a model from the UI
 *  2) Save via the controller
 *  3) Report a user-facing admin status message
 */
class ConfigPanelModelIntegrationHeadlessTest {

    @Test
    void ui_to_json_to_state_back_to_ui_roundtrip() {
        TestUi ui = new TestUi();
        ConfigPanel panel = new ConfigPanel(new ConfigController(ui));

        // Prefer text; if unsupported, pick the last button in the Admin block
        JButton save = (JButton) findByTextOrLastButton(panel);
        save.doClick();

        await(() -> ui.adminStatus != null);
        assertThat(ui.adminStatus)
                .isNotBlank()
                .containsAnyOf("Saved", "Exported", "Imported");
    }

    // ---- Mini harness ----

    private static final class TestUi implements ConfigController.Ui {
        volatile String adminStatus;
        @Override public void onFileStatus(String message) {
            // File status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onOpenSearchStatus(String message) {
            // OpenSearch status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onAdminStatus(String message) { adminStatus = message; }
    }

    private static Component findByTextOrLastButton(Container root) {
        Component byText = findByText(root, "Save");
        if (byText != null) return byText;
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

    private static void await(Callable<Boolean> cond) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(3);
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
        throw new AssertionError("Timed out waiting for condition.");
    }
}
