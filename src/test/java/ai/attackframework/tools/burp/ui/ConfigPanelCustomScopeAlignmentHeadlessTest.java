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
 * Headless tests for {@link ConfigPanel} custom-scope row behavior.
 *
 * <p>Verifies that:
 * <ul>
 *   <li>Row 0 has the radio button and no delete button.</li>
 *   <li>Subsequent rows use a placeholder in column&nbsp;1 and include a delete button.</li>
 *   <li>Field names compact/renumber correctly after deletion.</li>
 * </ul>
 *
 * <p>Tests interact through stable component names and visible controls — no reflection.
 * All UI interactions occur on the EDT.</p>
 */
class ConfigPanelCustomScopeAlignmentHeadlessTest {

    /**
     * Ensures that fields remain aligned and correctly renumbered when a row is deleted.
     */
    @Test
    void fields_remain_aligned_after_delete() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        JButton add = findAddButton(panel);
        runEdt(() -> {
            add.doClick();
            add.doClick();
            add.doClick();
        });

        List<JTextField> fields = findScopeFieldsSorted(panel);
        assertThat(fields).hasSize(4);

        // Delete the second row by clicking the row "Delete" button
        JTextField second = fields.get(1);
        JButton delete2 = findDeleteButtonForRow(second);
        runEdt(delete2::doClick);

        // Re-read fields after rebuild
        fields = findScopeFieldsSorted(panel);
        assertThat(fields).hasSize(3);

        // The first field keeps its base name "scope.custom.regex"
        assertThat(fields.getFirst().getName()).isEqualTo("scope.custom.regex");

        // Dynamically added fields keep numeric suffixes in visual order
        for (int i = 1; i < fields.size(); i++) {
            assertThat(fields.get(i).getName()).isEqualTo("scope.custom.regex." + (i + 1));
        }
    }

    /**
     * Verifies that only subsequent rows contain a delete button (row 0 should not).
     */
    @Test
    void first_field_has_no_delete_button() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        JButton add = findAddButton(panel);
        runEdt(() -> {
            add.doClick();
            add.doClick();
        });

        List<JTextField> fields = findScopeFieldsSorted(panel);
        assertThat(fields).hasSize(3);

        // The first row should NOT have a delete button
        assertThat(hasDeleteButton(fields.getFirst())).isFalse();

        // All subsequent rows SHOULD have a delete button
        for (int i = 1; i < fields.size(); i++) {
            assertThat(hasDeleteButton(fields.get(i))).isTrue();
        }
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

    private static boolean hasDeleteButton(JTextField field) {
        JPanel row = (JPanel) field.getParent();
        for (var c : row.getComponents()) {
            if (c instanceof JButton b && "Delete".equals(b.getText())) return true;
        }
        return false;
    }

    /** Return all scope text fields in visual order, sorted by numeric suffix (base field first). */
    private static List<JTextField> findScopeFieldsSorted(JComponent root) {
        List<JTextField> out = new ArrayList<>();
        collect(root, JTextField.class, out);
        out.removeIf(f -> f.getName() == null || !f.getName().startsWith("scope.custom.regex"));
        out.sort(Comparator.comparingInt(ConfigPanelCustomScopeAlignmentHeadlessTest::fieldIndex1));
        return out;
    }

    /** Index in 1-based order: base field -> 1; ".2" -> 2; ".3" -> 3; etc. */
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

    /** Run the given action on the EDT and block until it completes. */
    private static void runEdt(Runnable action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeAndWait(action);
        }
    }
}
