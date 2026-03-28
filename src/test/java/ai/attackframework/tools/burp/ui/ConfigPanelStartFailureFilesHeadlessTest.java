package ai.attackframework.tools.burp.ui;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import javax.swing.JButton;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBox;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

class ConfigPanelStartFailureFilesHeadlessTest {

    @Test
    void start_withFileRootThatIsNotWritableDirectory_revertsUi_and_reportsStatus() throws Exception {
        Path notADirectory = TestPathSupport.createFile("af-file-root-not-dir", ".tmp");
        try {
            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                JCheckBox openSearchEnabled = get(p, "openSearchSinkCheckbox");
                if (openSearchEnabled.isSelected()) {
                    openSearchEnabled.doClick();
                }

                JCheckBox filesEnabled = get(p, "fileSinkCheckbox");
                if (!filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                JRadioButton bulkNdjsonEnabled = get(p, "fileBulkNdjsonCheckbox");
                if (!bulkNdjsonEnabled.isSelected()) {
                    bulkNdjsonEnabled.doClick();
                }

                JTextField filePathField = get(p, "filePathField");
                filePathField.setText(notADirectory.toString());
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(get(panel, "controlStatus"));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).contains("Start aborted");
            assertThat(controlStatus.getText()).contains("File export preflight failed");
        } finally {
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void start_withFilesEnabledButNoFormatSelected_revertsUi_and_reportsStatus() throws Exception {
        try {
            AtomicReference<ConfigPanel> ref = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel();
                p.setSize(1000, 700);
                p.doLayout();

                JCheckBox openSearchEnabled = get(p, "openSearchSinkCheckbox");
                if (openSearchEnabled.isSelected()) {
                    openSearchEnabled.doClick();
                }

                JCheckBox filesEnabled = get(p, "fileSinkCheckbox");
                if (!filesEnabled.isSelected()) {
                    filesEnabled.doClick();
                }
                ButtonGroup fileFormatGroup = get(p, "fileFormatGroup");
                fileFormatGroup.clearSelection();

                JTextField filePathField = get(p, "filePathField");
                filePathField.setText(TestPathSupport.defaultUiFileRoot().toString());
                ref.set(p);
            });
            ConfigPanel panel = Objects.requireNonNull(ref.get());

            JButton startStop = Objects.requireNonNull(findByName(panel, "control.startStop", JButton.class));
            JTextArea controlStatus = Objects.requireNonNull(get(panel, "controlStatus"));

            SwingUtilities.invokeAndWait(startStop::doClick);
            waitForStoppedUi(startStop);

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatus.getText()).contains("Start aborted");
            assertThat(controlStatus.getText()).contains("select at least one file format");
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
