package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.JComponent;
import javax.swing.JCheckBox;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigPanelCustomScopeAlignmentHeadlessTest {

    @Test
    void fields_remain_aligned_after_delete() {
        ConfigPanel panel = new ConfigPanel();
        JButton addButton = getField(panel, "addCustomScopeButton");
        List<JTextField> fields = getField(panel, "customScopeFields");

        for (int i = 0; i < 3; i++) {
            addButton.doClick();
        }
        assertThat(fields).hasSize(4);

        JTextField second = fields.get(1);
        panel.removeCustomScopeFieldRow(second);

        assertThat(fields).hasSize(3);

        // The first field keeps its base name "scope.custom.regex"
        assertThat(fields.getFirst().getName()).isEqualTo("scope.custom.regex");

        // Dynamically added fields keep numeric suffixes
        for (int i = 1; i < fields.size(); i++) {
            assertThat(fields.get(i).getName())
                    .isEqualTo("scope.custom.regex." + (i + 1));
        }
    }

    @Test
    void regex_indicator_survives_rebuild() {
        ConfigPanel panel = new ConfigPanel();
        JButton addButton = getField(panel, "addCustomScopeButton");
        List<JTextField> fields = getField(panel, "customScopeFields");

        addButton.doClick();
        JTextField field = fields.get(1);
        field.setText("[unterminated"); // invalid regex
        panel.removeCustomScopeFieldRow(field);

        assertThat(fields).hasSize(1);
        JTextField first = fields.getFirst();
        first.setText("[unterminated");

        // Ensure toggle is selected before expecting regex indicator
        List<JCheckBox> toggles = getField(panel, "customScopeRegexToggles");
        toggles.getFirst().setSelected(true);

        // Trigger regex feedback update via reflection
        invokeMethod(panel, "updateCustomRegexFeedback");

        List<JLabel> indicators = getField(panel, "customScopeIndicators");
        assertThat(indicators.getFirst().getText()).isEqualTo("✖");
    }

    @Test
    void first_field_has_no_delete_button() {
        ConfigPanel panel = new ConfigPanel();
        JButton addButton = getField(panel, "addCustomScopeButton");
        List<JTextField> fields = getField(panel, "customScopeFields");

        addButton.doClick();
        addButton.doClick();

        // The first row should NOT have a delete button
        assertThat(hasDeleteButton(fields.getFirst())).isFalse();

        // All subsequent rows SHOULD have a delete button
        for (int i = 1; i < fields.size(); i++) {
            assertThat(hasDeleteButton(fields.get(i))).isTrue();
        }
    }

    private static boolean hasDeleteButton(JTextField field) {
        JComponent parent = (JComponent) field.getParent();
        for (var comp : parent.getComponents()) {
            if (comp instanceof JButton b && "Delete".equals(b.getText())) {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private static <T> T getField(Object target, String name) {
        try {
            var f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return (T) f.get(target);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void invokeMethod(Object target, String name, Object... args) {
        try {
            Class<?>[] argTypes = new Class<?>[args.length];
            for (int i = 0; i < args.length; i++) {
                argTypes[i] = args[i].getClass();
            }
            var m = target.getClass().getDeclaredMethod(name, argTypes);
            m.setAccessible(true);
            m.invoke(target, args);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
