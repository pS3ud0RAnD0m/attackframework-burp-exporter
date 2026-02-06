package ai.attackframework.tools.burp.ui;

import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import ai.attackframework.tools.burp.ui.controller.ConfigController;

/**
 * Verifies that toggling sink checkboxes enables/disables the corresponding
 * text fields and action buttons.
 */
class ConfigPanelSinkEnablementHeadlessTest {

    private ConfigPanel panel;

    @BeforeEach
    void setup() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel p = new ConfigPanel(new ConfigController(new NoopUi()));
            if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                p.setSize(1000, 700);
            }
            p.doLayout();
            ref.set(p);
        });
        panel = ref.get();
    }

    @Test
    void deselecting_sinks_disables_textfields_and_action_buttons() {
        // Files row (access private fields directly via shared Reflect helper).
        JCheckBox filesEnable = get(panel, "fileSinkCheckbox");
        JTextField filesPath  = get(panel, "filePathField");
        JButton filesCreate   = get(panel, "createFilesButton");

        // OpenSearch row
        JCheckBox osEnable  = get(panel, "openSearchSinkCheckbox");
        JTextField osUrl    = get(panel, "openSearchUrlField");
        JButton osTest      = get(panel, "testConnectionButton");
        JButton osIndexes   = get(panel, "createIndexesButton");

        // Ensure both sinks are enabled
        if (!filesEnable.isSelected()) filesEnable.doClick();
        if (!osEnable.isSelected()) osEnable.doClick();

        // Enabled assertions
        assertThat(filesPath.isEnabled()).isTrue();
        assertThat(filesCreate.isEnabled()).isTrue();
        assertThat(osUrl.isEnabled()).isTrue();
        assertThat(osTest.isEnabled()).isTrue();
        assertThat(osIndexes.isEnabled()).isTrue();

        // Disable both sinks
        if (filesEnable.isSelected()) filesEnable.doClick();
        if (osEnable.isSelected()) osEnable.doClick();

        // Disabled assertions
        assertThat(filesPath.isEnabled()).isFalse();
        assertThat(filesCreate.isEnabled()).isFalse();
        assertThat(osUrl.isEnabled()).isFalse();
        assertThat(osTest.isEnabled()).isFalse();
        assertThat(osIndexes.isEnabled()).isFalse();
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {
            // File status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onOpenSearchStatus(String message) {
            // OpenSearch status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onControlStatus(String message) {
            // Control status is not observed in this test; required by ConfigController.Ui
        }
    }
}
