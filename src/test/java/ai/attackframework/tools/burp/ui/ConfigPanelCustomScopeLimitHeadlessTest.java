package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
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

        JButton add = findAddButton(panel);
        // Grow to 100 rows using the visible Add action.
        for (int i = findScopeFieldsSorted(panel).size(); i < 100; i++) {
            runEdt(add::doClick);
        }

        List<JTextField> fields = findScopeFieldsSorted(panel);
        assertThat(fields).hasSize(100);
        assertThat(add.isEnabled()).isFalse();

        // Delete the last row via its Delete button
        JTextField last = fields.getLast();
        JButton delete = findDeleteButtonForRow(last);
        runEdt(delete::doClick);

        fields = findScopeFieldsSorted(panel);
        assertThat(fields).hasSize(99);
        assertThat(add.isEnabled()).isTrue();
    }

    /* ----------------------------- helpers ----------------------------- */

    private static JButton findAddButton(JComponent root) {
        JTextField first = firstScopeField(root);
        JPanel row = (JPanel) first.getParent();
        for (var c : row.getComponents()) {
            if (c instanceof JButton b && "Add".equals(b.getText())) return b;
        }
        throw new AssertionError("Add button not found in the first row");
    }

    private static JButton findDeleteButtonForRow(JTextField field) {
        JPanel row = (JPanel) field.getParent();
        for (var c : row.getComponents()) {
            if (c instanceof JButton b && "Delete".equals(b.getText())) return b;
        }
        throw new AssertionError("Delete button not found for row: " + field.getName());
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

    /** Finds the first-row scope text field by its stable component name. */
    private static JTextField firstScopeField(JComponent root) {
        List<JTextField> all = new ArrayList<>();
        collect(root, JTextField.class, all);
        for (JTextField f : all) {
            if ("scope.custom.regex".equals(f.getName())) return f;
        }
        throw new AssertionError("Component not found: scope.custom.regex (JTextField)");
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
