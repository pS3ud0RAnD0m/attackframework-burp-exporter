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
 * Headless tests for {@link ConfigPanel} custom-scope row behavior.
 *
 * <p>Verifies that:</p>
 * <ul>
 *   <li>Row 0 has the radio button and no delete button.</li>
 *   <li>Subsequent rows use a placeholder in column&nbsp;1 and include a delete button.</li>
 *   <li>Field names compact/renumber correctly after deletion.</li>
 *   <li>Regex indicator reflects validity after a rebuild.</li>
 * </ul>
 *
 * <p>These tests rely on reflective access via the shared {@code Reflect} helper to
 * minimize production visibility and keep the panel’s API surface small.</p>
 */
class ConfigPanelCustomScopeAlignmentHeadlessTest {

    /**
     * Ensures that fields remain aligned and correctly renumbered when a row is deleted.
     */
    @Test
    void fields_remain_aligned_after_delete() {
        ConfigPanel panel = new ConfigPanel();

        JButton addButton = get(panel, "addCustomScopeButton");
        List<JTextField> fields = get(panel, "customScopeFields");

        for (int i = 0; i < 3; i++) {
            addButton.doClick();
        }
        assertThat(fields).hasSize(4);

        JTextField second = fields.get(1);
        // Remove via private method
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

    /**
     * Ensures that a regex validity indicator survives a rebuild
     * (row removal followed by validation on the first row).
     */
    @Test
    void regex_indicator_survives_rebuild() {
        ConfigPanel panel = new ConfigPanel();

        JButton addButton = get(panel, "addCustomScopeButton");
        List<JTextField> fields = get(panel, "customScopeFields");

        addButton.doClick();
        JTextField field = fields.get(1);
        field.setText("[unterminated"); // invalid regex

        // Remove via private method (forces rebuild of the grid)
        callVoid(panel, "removeCustomScopeFieldRow", field);

        assertThat(fields).hasSize(1);

        // Re-validate on the first row after rebuild
        JTextField first = fields.getFirst();
        first.setText("[unterminated"); // triggers binder via DocumentListener

        // Ensure toggle is selected before expecting indicator
        List<JCheckBox> toggles = get(panel, "customScopeRegexToggles");
        toggles.getFirst().setSelected(true); // triggers binder via ActionListener

        // Read indicator; binder updates it from the listeners above
        List<JLabel> indicators = get(panel, "customScopeIndicators");
        assertThat(indicators.getFirst().getText()).isEqualTo("✖");
    }

    /**
     * Verifies that only subsequent rows contain a delete button (row 0 should not).
     */
    @Test
    void first_field_has_no_delete_button() {
        ConfigPanel panel = new ConfigPanel();

        JButton addButton = get(panel, "addCustomScopeButton");
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

    /**
     * Returns whether the row containing the given field has a delete button.
     *
     * @param field scope field under test
     * @return {@code true} if the parent row contains a {@code JButton} with text {@code "Delete"}
     */
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
