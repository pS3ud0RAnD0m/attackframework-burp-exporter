package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigPanelSinkEnablementHeadlessTest {

    @Test
    void deselecting_sinks_disables_only_textfields_not_action_buttons() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        JCheckBox filesEnable   = get(panel, "fileSinkCheckbox", JCheckBox.class);
        JTextField filesPath    = get(panel, "filePathField", JTextField.class);
        JButton createFiles     = get(panel, "createFilesButton", JButton.class);

        JCheckBox osEnable      = get(panel, "openSearchSinkCheckbox", JCheckBox.class);
        JTextField osUrl        = get(panel, "openSearchUrlField", JTextField.class);
        JButton osTest          = get(panel, "testConnectionButton", JButton.class);
        JButton osCreateIndexes = get(panel, "createIndexesButton", JButton.class);

        // Baseline: action buttons should be enabled
        assertThat(createFiles.isEnabled()).isTrue();
        assertThat(osTest.isEnabled()).isTrue();
        assertThat(osCreateIndexes.isEnabled()).isTrue();

        // Files: deselect -> textfield disabled, button remains enabled
        SwingUtilities.invokeAndWait(() -> filesEnable.setSelected(false));
        assertThat(filesPath.isEnabled()).isFalse();
        assertThat(createFiles.isEnabled()).isTrue();

        // Files: reselect -> textfield enabled, button remains enabled
        SwingUtilities.invokeAndWait(() -> filesEnable.setSelected(true));
        assertThat(filesPath.isEnabled()).isTrue();
        assertThat(createFiles.isEnabled()).isTrue();

        // OpenSearch: deselect -> textfield disabled, buttons remain enabled
        SwingUtilities.invokeAndWait(() -> osEnable.setSelected(false));
        assertThat(osUrl.isEnabled()).isFalse();
        assertThat(osTest.isEnabled()).isTrue();
        assertThat(osCreateIndexes.isEnabled()).isTrue();

        // OpenSearch: reselect -> textfield enabled, buttons remain enabled
        SwingUtilities.invokeAndWait(() -> osEnable.setSelected(true));
        assertThat(osUrl.isEnabled()).isTrue();
        assertThat(osTest.isEnabled()).isTrue();
        assertThat(osCreateIndexes.isEnabled()).isTrue();
    }

    private static <T> T get(Object target, String fieldName, Class<T> type) throws Exception {
        var f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return type.cast(f.get(target));
    }
}
