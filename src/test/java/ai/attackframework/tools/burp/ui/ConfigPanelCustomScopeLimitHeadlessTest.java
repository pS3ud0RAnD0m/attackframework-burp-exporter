package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigPanelCustomScopeLimitHeadlessTest {

    @Test
    void add_button_disables_at_100_and_re_enables_after_delete() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        JButton addBtn = (JButton) getField(panel, "addCustomScopeButton");
        @SuppressWarnings("unchecked")
        List<JTextField> fields = (List<JTextField>) getField(panel, "customScopeFields");
        @SuppressWarnings("unchecked")
        List<JButton> deleteButtons = (List<JButton>) getField(panel, "customScopeDeleteButtons");

        assertThat(fields).hasSize(1);
        assertThat(addBtn.isEnabled()).isTrue();

        // Add until we reach 100 fields
        while (fields.size() < 100) {
            SwingUtilities.invokeAndWait(addBtn::doClick);
        }
        assertThat(fields).hasSize(100);
        assertThat(addBtn.isEnabled()).isFalse();

        // Delete the last extra field
        JButton lastDelete = deleteButtons.getLast();
        assertThat(lastDelete).isNotNull();
        SwingUtilities.invokeAndWait(lastDelete::doClick);

        assertThat(fields).hasSize(99);
        assertThat(addBtn.isEnabled()).isTrue();
    }

    private static Object getField(Object target, String fieldName) throws Exception {
        var f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return f.get(target);
    }
}
