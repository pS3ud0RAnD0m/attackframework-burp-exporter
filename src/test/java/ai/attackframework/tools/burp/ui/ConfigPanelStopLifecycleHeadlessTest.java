package ai.attackframework.tools.burp.ui;

import static ai.attackframework.tools.burp.testutils.Reflect.getStatic;
import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.sinks.FindingsIndexReporter;
import ai.attackframework.tools.burp.sinks.ProxyWebSocketIndexReporter;
import ai.attackframework.tools.burp.sinks.SettingsIndexReporter;
import ai.attackframework.tools.burp.sinks.SitemapIndexReporter;
import ai.attackframework.tools.burp.sinks.ToolIndexStatsReporter;
import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

class ConfigPanelStopLifecycleHeadlessTest {

    @Test
    void stopButton_quiescesBackgroundReporters() throws Exception {
        try {
            RuntimeConfig.setExportRunning(true);
            ToolIndexStatsReporter.start();
            SettingsIndexReporter.start();
            FindingsIndexReporter.start();
            SitemapIndexReporter.start();
            ProxyWebSocketIndexReporter.start();

            ConfigPanel panel = newPanelOnEdt();
            JButton stopButton = (JButton) findByName(panel, "control.startStop");
            assertThat(stopButton).isNotNull();

            runEdt(stopButton::doClick);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat((ScheduledExecutorService) getStatic(ToolIndexStatsReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(SettingsIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(FindingsIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(SitemapIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(ProxyWebSocketIndexReporter.class, "scheduler")).isNull();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void startThenStop_updatesVisibleControlStatusThroughConfigPanelFlow() throws Exception {
        try {
            RuntimeConfig.setExportRunning(false);
            ConfigPanel panel = newPanelOnEdt();
            JButton startStop = (JButton) findByName(panel, "control.startStop");
            JTextArea controlStatus = findByName(panel, "control.status", JTextArea.class);
            JCheckBox openSearchEnabled = findByName(panel, "os.enable", JCheckBox.class);
            JTextField openSearchUrlField = getField(panel, "openSearchUrlField");
            assertThat(startStop).isNotNull();
            assertThat(controlStatus).isNotNull();

            runEdt(() -> {
                openSearchUrlField.setText("");
                if (openSearchEnabled.isSelected()) {
                    openSearchEnabled.doClick();
                }
            });

            runEdt(startStop::doClick);
            waitForControlStatus(controlStatus, "Running");

            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(startStop.getText()).isEqualTo("Stop");
            assertThat(controlStatus.getText()).isEqualTo("Running");

            runEdt(startStop::doClick);
            waitForControlStatus(controlStatus, "Stopped");

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).isEqualTo("Stopped");
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    private static ConfigPanel newPanelOnEdt() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel(new ConfigController(new ConfigController.Ui() {
                @Override public void onFileStatus(String message) { }
                @Override public void onOpenSearchStatus(String message) { }
                @Override public void onControlStatus(String message) { }
            }));
            panel.setSize(1000, 700);
            panel.doLayout();
            ref.set(panel);
        });
        return ref.get();
    }

    private static <T> T getField(Object target, String fieldName) {
        try {
            java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            @SuppressWarnings("unchecked")
            T value = (T) field.get(target);
            return value;
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    private static void runEdt(Runnable runnable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
    }

    private static void waitForControlStatus(JTextArea controlStatus, String expected) {
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
            if (expected.equals(controlStatus.getText())) {
                return;
            }
            java.util.concurrent.locks.LockSupport.parkNanos(100_000_000L);
        }
        throw new AssertionError("Control status did not reach expected value: " + expected);
    }

    private static Component findByName(Container root, String name) {
        if (name.equals(root.getName())) {
            return root;
        }
        for (Component child : root.getComponents()) {
            if (name.equals(child.getName())) {
                return child;
            }
            if (child instanceof Container nested) {
                Component found = findByName(nested, name);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        Component found = findByName(root, name);
        if (found == null) {
            return null;
        }
        if (!type.isInstance(found)) {
            throw new AssertionError("Component found for " + name + " but was not a " + type.getSimpleName());
        }
        return type.cast(found);
    }
}
