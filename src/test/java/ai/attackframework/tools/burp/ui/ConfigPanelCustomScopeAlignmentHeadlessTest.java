package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTextField;
import java.util.List;

import static ai.attackframework.tools.burp.testutils.Reflect.callVoid;
import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies custom-scope row alignment and behavior:
 * - Row 0 has the radio and no delete button.
 * - Subsequent rows use a placeholder in col 1 and include a delete button.
 * - Field names compact/renumber after deletion.
 * - Regex indicator reflects validity when requested.
 */
class ConfigPanelCustomScopeAlignmentHeadlessTest {

    @Test
    void fields_remain_aligned_after_delete() {
        ConfigPanel panel = new ConfigPanel();

        JButton addButton = get(panel, "addCustomScopeButton");
        @SuppressWarnings("unchecked")
        List<JTextField> fields = get(panel, "customScopeFields");

        for (int i = 0; i < 3; i++) {
            addButton.doClick();
        }
        assertThat(fields).hasSize(4);

        JTextField second = fields.get(1);
        // remove via private method
        callVoid(panel, "removeCustomScopeFieldRow", second);

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

        JButton addButton = get(panel, "addCustomScopeButton");
        @SuppressWarnings("unchecked")
        List<JTextField> fields = get(panel, "customScopeFields");

        addButton.doClick();
        JTextField field = fields.get(1);
        field.setText("[unterminated"); // invalid regex

        // remove via private method (forces rebuild)
        callVoid(panel, "removeCustomScopeFieldRow", field);

        assertThat(fields).hasSize(1);
        JTextField first = fields.getFirst();
        first.setText("[unterminated");

        // Ensure toggle is selected before expecting indicator
        @SuppressWarnings("unchecked")
        List<JCheckBox> toggles = get(panel, "customScopeRegexToggles");
        toggles.getFirst().setSelected(true);

        // Trigger regex feedback
        callVoid(panel, "updateCustomRegexFeedback");

        @SuppressWarnings("unchecked")
        List<JLabel> indicators = get(panel, "customScopeIndicators");
        assertThat(indicators.getFirst().getText()).isEqualTo("✖");
    }

    @Test
    void first_field_has_no_delete_button() {
        ConfigPanel panel = new ConfigPanel();

        JButton addButton = get(panel, "addCustomScopeButton");
        @SuppressWarnings("unchecked")
        List<JTextField> fields = get(panel, "customScopeFields");

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
}
