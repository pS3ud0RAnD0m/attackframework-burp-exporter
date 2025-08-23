package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JTextField;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigPanelCustomScopeLimitHeadlessTest {

    @Test
    void add_button_disables_at_100_and_re_enables_after_delete() {
        ConfigPanel panel = new ConfigPanel();

        JButton addButton = panel.addCustomScopeButton;
        List<JTextField> fields = panel.customScopeFields;

        // Add up to 100 fields
        for (int i = fields.size(); i < 100; i++) {
            addButton.doClick();
        }

        assertThat(fields).hasSize(100);
        assertThat(addButton.isEnabled()).isFalse();

        // Remove one field (simulate by directly calling remove on the last field)
        JTextField lastField = fields.getLast();
        panel.removeCustomScopeFieldRow(lastField);

        assertThat(fields).hasSize(99);
        assertThat(addButton.isEnabled()).isTrue();
    }
}
