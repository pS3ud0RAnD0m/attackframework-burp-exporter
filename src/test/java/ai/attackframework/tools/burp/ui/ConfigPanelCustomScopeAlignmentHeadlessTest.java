package ai.attackframework.tools.burp.ui;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

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

        // Enable the Custom scope so Add/Delete are active
        JRadioButton custom = findByName(panel, "scope.custom", JRadioButton.class);
        runEdt(() -> custom.setSelected(true));

        JButton add = findAddButton(panel);
        runEdt(() -> {
            add.doClick();
            add.doClick();
            add.doClick();
        });

        List<JTextField> fields = findScopeFieldsSorted(panel);
        assertThat(fields).hasSize(4);

        // Delete the second row via its named Delete button
        JTextField second = fields.get(1);
        JButton delete2 = findDeleteButtonForRow(panel, second);
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

        // Enable the Custom scope so Add/Delete are active
        JRadioButton custom = findByName(panel, "scope.custom", JRadioButton.class);
        runEdt(() -> custom.setSelected(true));

        JButton add = findAddButton(panel);
        runEdt(() -> {
            add.doClick();
            add.doClick();
        });

        List<JTextField> fields = findScopeFieldsSorted(panel);
        assertThat(fields).hasSize(3);

        // The first row should NOT have a delete button (no button named scope.custom.delete.1)
        assertThat(hasDeleteButton(panel, fields.getFirst())).isFalse();

        // All subsequent rows SHOULD have a delete button
        for (int i = 1; i < fields.size(); i++) {
            assertThat(hasDeleteButton(panel, fields.get(i))).isTrue();
        }
    }

    /* ----------------------------- helpers ----------------------------- */

    private static JButton findAddButton(JComponent root) {
        // Named lookup to decouple from container topology
        return findByName(root, "scope.custom.add", JButton.class);
    }

    private static JButton findDeleteButtonForRow(JComponent root, JTextField field) {
        int idx = indexFromFieldName(field);
        String name = "scope.custom.delete." + idx;
        return findByName(root, name, JButton.class);
    }

    private static boolean hasDeleteButton(JComponent root, JTextField field) {
        int idx = indexFromFieldName(field);
        String name = "scope.custom.delete." + idx;
        return findOptionalByName(root, name, JButton.class) != null;
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

    private static int indexFromFieldName(JTextField f) {
        String n = f.getName();
        if ("scope.custom.regex".equals(n)) return 1;
        int dot = n.lastIndexOf('.');
        if (dot < 0) throw new IllegalArgumentException("Unexpected field name: " + n);
        return Integer.parseInt(n.substring(dot + 1));
    }

    private static <T extends JComponent> T findByName(JComponent root, String name, Class<T> type) {
        T c = findOptionalByName(root, name, type);
        if (c != null) return c;
        throw new AssertionError("Component not found: " + name + " (" + type.getSimpleName() + ")");
    }

    private static <T extends JComponent> T findOptionalByName(JComponent root, String name, Class<T> type) {
        List<T> all = new ArrayList<>();
        collect(root, type, all);
        for (T c : all) {
            if (name.equals(c.getName())) return c;
        }
        return null;
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
