package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JTextField;
import java.util.List;

import static ai.attackframework.tools.burp.testutils.Reflect.callVoid;
import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the Add button disables at 100 custom-scope rows and
 * re-enables after one row is removed. Private members are accessed
 * via the shared Reflect test utility to keep production visibility minimal.
 */
class ConfigPanelCustomScopeLimitHeadlessTest {

    @Test
    void add_button_disables_at_100_and_re_enables_after_delete() {
        ConfigPanel panel = new ConfigPanel();

        JButton addButton = get(panel, "addCustomScopeButton");
        @SuppressWarnings("unchecked")
        List<JTextField> fields = get(panel, "customScopeFields");

        // Grow to 100 rows using the public Add action.
        for (int i = fields.size(); i < 100; i++) {
            addButton.doClick();
        }

        assertThat(fields).hasSize(100);
        assertThat(addButton.isEnabled()).isFalse();

        // Remove one row via the private method and confirm re-enable.
        JTextField lastField = fields.getLast();
        callVoid(panel, "removeCustomScopeFieldRow", lastField);

        assertThat(fields).hasSize(99);
        assertThat(addButton.isEnabled()).isTrue();
    }
}
