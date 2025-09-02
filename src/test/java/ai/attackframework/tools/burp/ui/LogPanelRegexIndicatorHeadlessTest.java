package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Headless tests for the regex validity indicators in {@link LogPanel}.
 *
 * <p>These tests locate indicator labels by stable component names rather than reflecting
 * private fields. This is refactor-safe and aligns with best practices for UI testing.</p>
 */
class LogPanelRegexIndicatorHeadlessTest {

    /**
     * Verifies the filter indicator shows ✖ for an invalid pattern, ✓ for a valid one,
     * and hides when regex mode is disabled.
     */
    @Test
    void filter_regex_indicator_shows_check_or_cross() {
        LogPanel panel = new LogPanel();

        JTextField field = byName(panel, "log.filter.text", JTextField.class);
        JCheckBox regex = byName(panel, "log.filter.regex", JCheckBox.class);
        JLabel indicator = byName(panel, "log.filter.regex.indicator", JLabel.class);

        // Turn regex mode on and enter an invalid pattern
        regex.setSelected(true);
        flushEdt();
        field.setText("[unterminated");
        flushEdt();
        assertThat(indicator.getText()).as("invalid regex shows ✖").isEqualTo("✖");

        // Now enter a valid pattern
        field.setText("a.*b");
        flushEdt();
        assertThat(indicator.getText()).as("valid regex shows ✓").isEqualTo("✓");

        // Turn regex mode off — indicator should hide
        regex.setSelected(false);
        flushEdt();
        assertThat(indicator.isVisible()).as("indicator hides when regex mode is off").isFalse();
    }

    /**
     * Verifies the search indicator shows ✖ for an invalid pattern, ✓ for a valid one,
     * and hides when regex mode is disabled.
     */
    @Test
    void search_regex_indicator_shows_check_or_cross() {
        LogPanel panel = new LogPanel();

        JTextField field = byName(panel, "log.search.field", JTextField.class);
        JCheckBox regex = byName(panel, "log.search.regex", JCheckBox.class);
        JLabel indicator = byName(panel, "log.search.regex.indicator", JLabel.class);

        // Turn regex mode on and enter an invalid pattern
        regex.setSelected(true);
        flushEdt();
        field.setText("[unterminated");
        flushEdt();
        assertThat(indicator.getText()).as("invalid regex shows ✖").isEqualTo("✖");

        // Now enter a valid pattern
        field.setText("^foo.*bar$");
        flushEdt();
        assertThat(indicator.getText()).as("valid regex shows ✓").isEqualTo("✓");

        // Turn regex mode off — indicator should hide
        regex.setSelected(false);
        flushEdt();
        assertThat(indicator.isVisible()).as("indicator hides when regex mode is off").isFalse();
    }

    /**
     * Breadth-first search for a component by {@link Component#getName() name} and type.
     *
     * @param root container to search
     * @param name expected component name
     * @param type expected component type
     * @return the first matching component
     * @throws AssertionError if not found
     */
    private static <T extends Component> T byName(Container root, String name, Class<T> type) {
        Deque<Component> q = new ArrayDeque<>();
        q.add(root);
        while (!q.isEmpty()) {
            Component c = q.removeFirst();
            if (name.equals(c.getName()) && type.isInstance(c)) {
                return type.cast(c);
            }
            if (c instanceof Container cont) {
                Collections.addAll(q, cont.getComponents());
            }
        }
        throw new AssertionError("Component not found: name=" + name + ", type=" + type.getSimpleName());
    }

    /** Flush the EDT so listener-side effects (binder updates) are applied before assertions. */
    private static void flushEdt() {
        try {
            SwingUtilities.invokeAndWait(() -> { /* no-op */ });
        } catch (Exception e) {
            throw new RuntimeException("EDT flush failed", e);
        }
    }
}
