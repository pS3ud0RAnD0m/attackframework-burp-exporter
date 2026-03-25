package ai.attackframework.tools.burp.ui;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.sinks.TrafficExportQueue;
import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

@Tag("integration")
class ConfigPanelStartFailureAuthIT {

    private ConfigPanel panel;

    @Test
    void start_withInvalidAuth_revertsUi_and_clearsQueuedExportWork() throws Exception {
        try {
            Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                JCheckBox openSearchEnabled = get(p, "openSearchSinkCheckbox");
                if (!openSearchEnabled.isSelected()) {
                    openSearchEnabled.doClick();
                }

                JTextField openSearchUrlField = get(p, "openSearchUrlField");
                openSearchUrlField.setText(OpenSearchReachable.BASE_URL);

                JComboBox<String> authCombo = get(p, "openSearchAuthTypeCombo");
                authCombo.setSelectedItem("Basic");

                JTextField userField = get(p, "openSearchUserField");
                JPasswordField passwordField = get(p, "openSearchPasswordField");
                userField.setText("definitely-wrong");
                passwordField.setText("definitely-wrong");

                ref.set(p);
            });
            panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea openSearchStatus = Objects.requireNonNull(get(panel, "openSearchStatus"));
            JTextArea controlStatus = Objects.requireNonNull(get(panel, "controlStatus"));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(openSearchStatus.getText()).contains("401");
            assertThat(controlStatus.getText()).contains("Start aborted");

            // Give any late worker transitions a brief chance to enqueue if cleanup is incomplete.
            LockSupport.parkNanos(1_500_000_000L);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(ExportStats.getQueueSize("tool")).isZero();
            assertThat(ExportStats.getQueueSize("traffic")).isZero();
            assertThat(ExportStats.getQueueSize("settings")).isZero();
            assertThat(ExportStats.getQueueSize("sitemap")).isZero();
            assertThat(ExportStats.getQueueSize("findings")).isZero();
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
        } finally {
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    private static void waitForStoppedUi(JButton startStop) {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            try {
                SwingUtilities.invokeAndWait(() -> { });
            } catch (java.lang.InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            } catch (java.lang.reflect.InvocationTargetException e) {
                throw new RuntimeException(e);
            }
            if (!RuntimeConfig.isExportRunning() && "Start".equals(startStop.getText())) {
                return;
            }
            LockSupport.parkNanos(100_000_000L);
        }
        throw new AssertionError("Start button did not revert to stopped state within timeout");
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        for (Component component : root.getComponents()) {
            String componentName = component.getName();
            if (type.isInstance(component) && componentName != null && name.equals(componentName)) {
                return type.cast(component);
            }
            if (component instanceof Container child) {
                T nested = findByName(child, name, type);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }
}
