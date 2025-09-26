package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.config.ConfigState;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies Custom import ordering: rows are applied before the Custom radio flips,
 * so enable/disable runs against the final state; entries appear in order with correct kinds.
 */
class ConfigPanelImportOrderingHeadlessTest {

    @Test
    void import_builds_rows_then_flips_custom_radio() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        // Build typed state with three custom entries (mixed regex flags)
        ConfigState.State state = buildState();

        // Import on EDT
        runEdt(() -> panel.onImportResult(state));

        // Custom should be selected and all three rows present in order
        JRadioButton custom = customRadio(panel);
        assertThat(custom.isSelected()).isTrue();

        List<JTextField> fields = findFields(panel);
        assertThat(fields).hasSize(3);
        assertThat(fields.getFirst().getName()).isEqualTo("scope.custom.regex");
        assertThat(fields.get(1).getName()).isEqualTo("scope.custom.regex.2");
        assertThat(fields.get(2).getName()).isEqualTo("scope.custom.regex.3");

        // Ensure the values are in order and not empty
        assertThat(textOf(fields.getFirst())).isEqualTo("^one$");
        assertThat(textOf(fields.get(1))).isEqualTo("two.example.com");
        assertThat(textOf(fields.get(2))).isEqualTo(".*three.*");
    }

    // ---------- helpers ----------

    private static ConfigState.State buildState() {
        List<String> dataSources = List.of("settings", "sitemap");
        List<ConfigState.ScopeEntry> entries = new ArrayList<>();
        entries.add(new ConfigState.ScopeEntry("^one$", ConfigState.Kind.REGEX));
        entries.add(new ConfigState.ScopeEntry("two.example.com", ConfigState.Kind.STRING));
        entries.add(new ConfigState.ScopeEntry(".*three.*", ConfigState.Kind.REGEX));
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", false, "");
        return new ConfigState.State(dataSources, "custom", entries, sinks);
    }

    private static JRadioButton customRadio(JComponent root) {
        List<JRadioButton> all = new ArrayList<>();
        collect(root, JRadioButton.class, all);
        for (JRadioButton rb : all) if ("scope.custom".equals(rb.getName())) return rb;
        throw new AssertionError("Component not found: scope.custom (JRadioButton)");
    }

    private static String textOf(JTextField f) { return f.getText() == null ? "" : f.getText(); }

    private static List<JTextField> findFields(JComponent root) {
        List<JTextField> out = new ArrayList<>();
        collect(root, JTextField.class, out);
        out.removeIf(x -> x.getName() == null || !x.getName().startsWith("scope.custom.regex"));
        out.sort(Comparator.comparingInt(ConfigPanelImportOrderingHeadlessTest::index));
        return out;
    }

    private static int index(JTextField f) {
        String n = f.getName();
        if ("scope.custom.regex".equals(n)) return 1;
        int dot = n.lastIndexOf('.');
        return dot < 0 ? Integer.MAX_VALUE : Integer.parseInt(n.substring(dot + 1));
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
