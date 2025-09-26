package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.Rectangle;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Asserts column alignment: all text fields share the same left x, and all buttons share the same left x.
 */
class ConfigPanelColumnAlignmentHeadlessTest {

    @Test
    void fields_and_buttons_share_left_edge_across_rows() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        // Enable Custom and add rows
        JRadioButton custom = findByName(panel, "scope.custom", JRadioButton.class);
        runEdt(() -> custom.setSelected(true));
        JButton add = findByName(panel, "scope.custom.add", JButton.class);
        runEdt(() -> { add.doClick(); add.doClick(); });

        layoutPanel(panel);

        List<JTextField> fields = findFieldsSorted(panel);
        int fx = bounds(fields.getFirst()).x;
        for (JTextField f : fields) assertThat(bounds(f).x).isEqualTo(fx);

        List<JButton> dels = findDeletes(panel);
        if (!dels.isEmpty()) {
            int bx = bounds(dels.getFirst()).x;
            for (JButton b : dels) assertThat(bounds(b).x).isEqualTo(bx);
        }
    }

    // ---------- helpers ----------

    private static List<JButton> findDeletes(JComponent root) {
        List<JButton> out = new ArrayList<>();
        collect(root, JButton.class, out);
        out.removeIf(b -> b.getName() == null || !b.getName().startsWith("scope.custom.delete."));
        out.sort(Comparator.comparingInt(ConfigPanelColumnAlignmentHeadlessTest::btnIndex));
        return out;
    }

    private static int btnIndex(JButton b) {
        String n = b.getName();
        int dot = n.lastIndexOf('.');
        return dot < 0 ? Integer.MAX_VALUE : Integer.parseInt(n.substring(dot + 1));
    }

    private static Rectangle bounds(JComponent c) { return c.getBounds(); }

    private static void layoutPanel(ConfigPanel panel) throws Exception {
        runEdt(() -> {
            panel.setSize(1000, 800);
            panel.doLayout();
        });
    }

    private static List<JTextField> findFieldsSorted(JComponent root) {
        List<JTextField> out = new ArrayList<>();
        collect(root, JTextField.class, out);
        out.removeIf(x -> x.getName() == null || !x.getName().startsWith("scope.custom.regex"));
        out.sort(Comparator.comparingInt(ConfigPanelColumnAlignmentHeadlessTest::index));
        return out;
    }

    private static int index(JTextField f) {
        String n = f.getName();
        if ("scope.custom.regex".equals(n)) return 1;
        int dot = n.lastIndexOf('.');
        return dot < 0 ? Integer.MAX_VALUE : Integer.parseInt(n.substring(dot + 1));
    }

    private static <T extends JComponent> T findByName(JComponent root, String name, Class<T> type) {
        List<T> all = new ArrayList<>();
        collect(root, type, all);
        for (T c : all) if (name.equals(c.getName())) return c;
        throw new AssertionError("Component not found: " + name + " (" + type.getSimpleName() + ")");
    }

    private static <T extends JComponent> void collect(JComponent root, Class<T> type, List<T> out) {
        if (type.isInstance(root)) out.add(type.cast(root));
        for (var comp : root.getComponents()) if (comp instanceof JComponent jc) collect(jc, type, out);
    }

    private static void runEdt(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeAndWait(r);
    }
}
