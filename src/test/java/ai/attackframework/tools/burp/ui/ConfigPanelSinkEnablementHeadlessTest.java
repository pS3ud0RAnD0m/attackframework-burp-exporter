package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies sink enablement now disables the sink's action buttons when unchecked.
 */
class ConfigPanelSinkEnablementHeadlessTest {

    @Test
    void deselecting_sinks_disables_textfields_and_action_buttons() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        JCheckBox filesEnable   = get(panel, "fileSinkCheckbox", JCheckBox.class);
        JTextField filesPath    = get(panel, "filePathField", JTextField.class);
        JButton createFiles     = get(panel, "createFilesButton", JButton.class);

        JCheckBox osEnable      = get(panel, "openSearchSinkCheckbox", JCheckBox.class);
        JTextField osUrl        = get(panel, "openSearchUrlField", JTextField.class);
        JButton osTest          = get(panel, "testConnectionButton", JButton.class);
        JButton osCreateIndexes = get(panel, "createIndexesButton", JButton.class);

        // Baseline: when enabled, buttons and fields should be enabled
        assertThat(filesEnable.isSelected()).isTrue();
        assertThat(filesPath.isEnabled()).isTrue();
        assertThat(createFiles.isEnabled()).isTrue();

        assertThat(osEnable.isSelected()).isFalse();
        // OpenSearch initially disabled under current defaults
        assertThat(osUrl.isEnabled()).isFalse();
        assertThat(osTest.isEnabled()).isFalse();
        assertThat(osCreateIndexes.isEnabled()).isFalse();

        // Files: deselect → textfield and button disabled
        SwingUtilities.invokeAndWait(() -> filesEnable.setSelected(false));
        assertThat(filesPath.isEnabled()).isFalse();
        assertThat(createFiles.isEnabled()).isFalse();

        // Files: reselect → both enabled
        SwingUtilities.invokeAndWait(() -> filesEnable.setSelected(true));
        assertThat(filesPath.isEnabled()).isTrue();
        assertThat(createFiles.isEnabled()).isTrue();

        // OpenSearch: enable → url and both buttons enabled
        SwingUtilities.invokeAndWait(() -> osEnable.setSelected(true));
        assertThat(osUrl.isEnabled()).isTrue();
        assertThat(osTest.isEnabled()).isTrue();
        assertThat(osCreateIndexes.isEnabled()).isTrue();

        // OpenSearch: disable again → url and both buttons disabled
        SwingUtilities.invokeAndWait(() -> osEnable.setSelected(false));
        assertThat(osUrl.isEnabled()).isFalse();
        assertThat(osTest.isEnabled()).isFalse();
        assertThat(osCreateIndexes.isEnabled()).isFalse();
    }

    private static <T> T get(Object target, String fieldName, Class<T> type) throws Exception {
        var f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return type.cast(f.get(target));
    }
}
