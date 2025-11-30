package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import org.junit.jupiter.api.Test;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

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

    @Test
    void clicking_buttons_invokes_controller_and_posts_status() throws Exception {
        TestUi ui = new TestUi();
        ConfigPanel panel = new ConfigPanel(new ConfigController(ui));

        // Enable OpenSearch sink so OS buttons are actionable
        JCheckBox osEnable = (JCheckBox) findByName(panel, "os.enable");
        if (osEnable != null && !osEnable.isSelected()) osEnable.doClick();

        JButton testConn  = (JButton) find(panel, "os.test", "Test Connection");
        JButton createIdx = (JButton) find(panel, "os.createIndexes", "Create Indexes");
        JButton createFil = (JButton) find(panel, "files.create", "Create Files");

        CountDownLatch os1 = new CountDownLatch(1);
        CountDownLatch os2 = new CountDownLatch(1);
        CountDownLatch fs1 = new CountDownLatch(1);

        new Thread(() -> { await(() -> ui.osMsg != null); os1.countDown(); }).start();
        new Thread(() -> { await(() -> ui.osMsg != null); os2.countDown(); }).start();
        new Thread(() -> { await(() -> ui.fileMsg != null); fs1.countDown(); }).start();

        testConn.doClick();
        createIdx.doClick();
        createFil.doClick();

        assertThat(os1.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(os2.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(fs1.await(3, TimeUnit.SECONDS)).isTrue();

        assertThat(ui.osMsg).isNotBlank();
        assertThat(ui.fileMsg).isNotBlank();
    }

    // ---- helpers ----

    private static Component find(Container root, String name, String fallbackText) {
        Component byName = findByName(root, name);
        if (byName != null) return byName;
        return findByText(root, fallbackText);
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
    }
}
