package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the Add button disables at 100 custom-scope rows and
 * re-enables after one row is removed. Tests interact via visible controls
 * and stable component names — no reflection.
 */
class ConfigPanelCustomScopeLimitHeadlessTest {

    @Test
    void add_button_disables_at_100_and_re_enables_after_delete() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        // Enable the Custom scope so Add/Delete are active
        JRadioButton custom = findByName(panel, "scope.custom", JRadioButton.class);
        runEdt(() -> custom.setSelected(true));

        JButton add = findAddButton(panel);
        // Grow to 100 rows using the visible Add action.
        for (int i = findScopeFieldsSorted(panel).size(); i < 100; i++) {
            runEdt(add::doClick);
        }

        List<JTextField> fields = findScopeFieldsSorted(panel);
        assertThat(fields).hasSize(100);
        assertThat(add.isEnabled()).isFalse();

        // Delete the last row via its named Delete button
        JTextField last = fields.getLast();
        JButton delete = findDeleteButtonForRow(panel, last);
        runEdt(delete::doClick);

        fields = findScopeFieldsSorted(panel);
        assertThat(fields).hasSize(99);
        assertThat(add.isEnabled()).isTrue();
    }

    /* ----------------------------- helpers ----------------------------- */

    private static JButton findAddButton(JComponent root) {
        return findByName(root, "scope.custom.add", JButton.class);
    }

    private static JButton findDeleteButtonForRow(JComponent root, JTextField field) {
        int idx = indexFromFieldName(field);
        String name = "scope.custom.delete." + idx;
        return findByName(root, name, JButton.class);
    }

    private static List<JTextField> findScopeFieldsSorted(JComponent root) {
        List<JTextField> out = new ArrayList<>();
        collect(root, JTextField.class, out);
        out.removeIf(f -> f.getName() == null || !f.getName().startsWith("scope.custom.regex"));
        out.sort(Comparator.comparingInt(ConfigPanelCustomScopeLimitHeadlessTest::fieldIndex1));
        return out;
    }

    private static int fieldIndex1(JTextField f) {
        String n = f.getName();
        if ("scope.custom.regex".equals(n)) return 1;
        int dot = n.lastIndexOf('.');
        if (dot < 0) return Integer.MAX_VALUE;
        return Integer.parseInt(n.substring(dot + 1));
    }

    private static int indexFromFieldName(JTextField f) {
        String n = f.getName();
        if ("scope.custom.regex".equals(n)) return 1;
        int dot = n.lastIndexOf('.');
        if (dot < 0) throw new IllegalArgumentException("Unexpected field name: " + n);
        return Integer.parseInt(n.substring(dot + 1));
    }

    private static <T extends JComponent> T findByName(JComponent root, String name, Class<T> type) {
        List<T> all = new ArrayList<>();
        collect(root, type, all);
        for (T c : all) {
            if (name.equals(c.getName())) return c;
        }
        throw new AssertionError("Component not found: " + name + " (" + type.getSimpleName() + ")");
    }

    private static <T extends JComponent> void collect(JComponent root, Class<T> type, List<T> out) {
        if (type.isInstance(root)) out.add(type.cast(root));
        for (var comp : root.getComponents()) {
            if (comp instanceof JComponent jc) collect(jc, type, out);
        }
    }

    private static void runEdt(Runnable action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeAndWait(action);
        }
    }
}
