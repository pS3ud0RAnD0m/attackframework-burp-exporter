package ai.attackframework.tools.burp.ui;

import static ai.attackframework.tools.burp.testutils.Reflect.getStatic;
import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
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

    private static void runEdt(Runnable runnable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
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
}
