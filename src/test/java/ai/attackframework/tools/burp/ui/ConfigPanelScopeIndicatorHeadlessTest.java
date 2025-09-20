package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Headless smoke test for the first-row scope indicator wiring in {@link ConfigPanel}.
 *
 * <p>Asserts that:
 * <ul>
 *   <li>When regex mode is enabled and the first field contains an invalid pattern,
 *       the indicator shows {@code ✖} and is visible.</li>
 *   <li>When regex mode is disabled, the indicator hides.</li>
 * </ul>
 *
 * <p>Tests interact through stable names and real UI events — no reflection.
 * All UI actions are flushed on the EDT.</p>
 */
class ConfigPanelScopeIndicatorHeadlessTest {

    @Test
    void first_row_indicator_shows_cross_for_invalid_and_hides_when_off() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        JTextField firstField = findByName(panel, "scope.custom.regex", JTextField.class);
        JLabel firstIndicator = findByName(panel, "scope.custom.regex.indicator.1", JLabel.class);
        JCheckBox firstToggle = findRegexToggleForRow(firstField);

        // Enable regex, set invalid pattern -> expect ✖ and visible
        runEdt(() -> {
            firstToggle.setSelected(true);
            firstField.setText("[unterminated");
        });
        assertThat(firstIndicator.isVisible()).as("indicator visible when regex is on").isTrue();
        assertThat(firstIndicator.getText()).as("invalid regex shows ✖").isEqualTo("✖");

        // Disable regex -> indicator hides (text may be cleared or remain; visibility is the contract)
        runEdt(() -> firstToggle.setSelected(false));
        assertThat(firstIndicator.isVisible()).as("indicator hides when regex mode is off").isFalse();
    }

    /* ----------------------------- helpers ----------------------------- */

    private static JCheckBox findRegexToggleForRow(JTextField fieldInRow) {
        JPanel row = (JPanel) fieldInRow.getParent();
        for (var c : row.getComponents()) {
            if (c instanceof JCheckBox cb && ".*".equals(cb.getText())) return cb;
        }
        throw new AssertionError("Regex toggle (.*) not found in row");
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

    /** Run the given action on the EDT and block until it completes. */
    private static void runEdt(Runnable action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeAndWait(action);
        }
    }
}
