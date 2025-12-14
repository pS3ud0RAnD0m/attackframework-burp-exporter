package ai.attackframework.tools.burp.ui;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies enable/disable contract: with Custom unchecked, controls are disabled but text remains;
 * with Custom checked, controls are enabled.
 */
class ConfigPanelCustomEnablementHeadlessTest {

    @Test
    void custom_toggle_disables_controls_but_preserves_text() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        // Initially unchecked (Burp Suite's selected) → controls disabled
        List<JTextField> initial = findFields(panel);
        assertThat(initial).hasSize(1);
        String initialText = textOf(initial.getFirst());
        assertThat(initial.getFirst().isEnabled()).isFalse();

        // Enable Custom and add a row
        JRadioButton custom = findByName(panel, "scope.custom", JRadioButton.class);
        runEdt(() -> custom.setSelected(true));
        JButton add = findByName(panel, "scope.custom.add", JButton.class);
        runEdt(add::doClick);

        List<JTextField> after = findFields(panel);
        assertThat(after).hasSize(2);
        for (JTextField f : after) assertThat(f.isEnabled()).isTrue();

        // Turn Custom off by selecting "Burp Suite's" (real user action)
        JRadioButton burp = findByName(panel, "scope.burp", JRadioButton.class);
        runEdt(() -> burp.setSelected(true));

        // Content remains, controls disabled
        List<JTextField> finalFields = findFields(panel);
        assertThat(finalFields).hasSize(2);
        for (JTextField f : finalFields) {
            assertThat(f.isEnabled()).isFalse();
            assertThat(textOf(f)).isNotNull(); // text remains
        }
        // seed text is still present
        assertThat(textOf(finalFields.getFirst())).isEqualTo(initialText);
    }

    // ---------- helpers ----------

    private static String textOf(JTextField f) { return f.getText() == null ? "" : f.getText(); }

    private static List<JTextField> findFields(JComponent root) {
        List<JTextField> out = new ArrayList<>();
        collect(root, JTextField.class, out);
        out.removeIf(x -> x.getName() == null || !x.getName().startsWith("scope.custom.regex"));
        return out;
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
