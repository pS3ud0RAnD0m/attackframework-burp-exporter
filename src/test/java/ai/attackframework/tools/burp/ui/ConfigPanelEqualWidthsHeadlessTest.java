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
 * Asserts equal-width invariants: all custom text fields share the same width
 * and Add/Delete buttons share the same width.
 */
class ConfigPanelEqualWidthsHeadlessTest {

    @Test
    void fields_and_buttons_have_equal_widths() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        // Enable Custom and add a few rows
        JRadioButton custom = findByName(panel, "scope.custom", JRadioButton.class);
        runEdt(() -> custom.setSelected(true));
        JButton add = findByName(panel, "scope.custom.add", JButton.class);

        runEdt(() -> {
            add.doClick();
            add.doClick();
        });

        // Make one field very long, then layout
        List<JTextField> fields = findFieldsSorted(panel);
        runEdt(() -> fields.get(1).setText("this.is.a.very.long.value.for.testing.equal.widths.example.com"));

        layoutPanel(panel);

        // All field widths equal
        int w0 = bounds(fields.getFirst()).width;
        for (JTextField f : fields) assertThat(bounds(f).width).isEqualTo(w0);

        // Add/Delete share equal width across rows
        List<JButton> buttons = new ArrayList<>();
        collect(panel, JButton.class, buttons);
        buttons.removeIf(b -> b.getName() == null || !(b.getName().equals("scope.custom.add") || b.getName().startsWith("scope.custom.delete.")));
        buttons.sort(Comparator.comparingInt(ConfigPanelEqualWidthsHeadlessTest::btnOrder));

        int bw = bounds(buttons.getFirst()).width;
        for (JButton b : buttons) assertThat(bounds(b).width).isEqualTo(bw);
    }

    // ---------- helpers ----------

    private static int btnOrder(JButton b) { return b.getName().equals("scope.custom.add") ? 0 : 1; }

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
        out.sort(Comparator.comparingInt(ConfigPanelEqualWidthsHeadlessTest::index));
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
