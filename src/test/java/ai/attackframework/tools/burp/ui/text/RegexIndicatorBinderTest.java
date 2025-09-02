package ai.attackframework.tools.burp.ui.text;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RegexIndicatorBinder}.
 *
 * <p>These tests assert that the binder:</p>
 * <ul>
 *   <li>Responds to text changes (document listener).</li>
 *   <li>Responds to toggle changes from both user clicks (action events) and
 *       programmatic {@code setSelected(...)} (item events).</li>
 *   <li>Hides the indicator when regex mode is off or the field is blank.</li>
 * </ul>
 *
 * <p>All UI mutations are followed by an EDT flush to ensure listener side effects
 * are applied before assertions.</p>
 */
class RegexIndicatorBinderTest {

    @Test
    void binder_updates_indicator_for_text_and_toggle_changes() throws Exception {
        // Arrange
        JTextField field = new JTextField();
        JCheckBox regexToggle = new JCheckBox(".*");
        JCheckBox caseToggle = new JCheckBox("Aa");
        JLabel indicator = new JLabel();

        // Bind (multiline = false for this test)
        AtomicReference<AutoCloseable> handle = new AtomicReference<>();
        runEdt(() -> handle.set(RegexIndicatorBinder.bind(field, regexToggle, caseToggle, false, indicator)));

        try (AutoCloseable ignored = handle.get()) {
            // Initially hidden (regex off)
            assertThat(indicator.isVisible()).as("initially hidden when regex is off").isFalse();

            // Enable regex and enter an invalid pattern
            runEdt(() -> {
                regexToggle.setSelected(true);
                field.setText("[unterminated");
            });
            assertThat(indicator.isVisible()).as("visible when regex is on").isTrue();
            assertThat(indicator.getText()).as("invalid shows ✖").isEqualTo("✖");

            // Replace with a valid pattern
            runEdt(() -> field.setText("a.*b"));
            assertThat(indicator.getText()).as("valid shows ✓").isEqualTo("✓");

            // Programmatically turn regex OFF → indicator hides
            runEdt(() -> regexToggle.setSelected(false));
            assertThat(indicator.isVisible()).as("hidden when regex mode is off").isFalse();

            // Turn regex ON with a blank field → remains hidden
            runEdt(() -> {
                regexToggle.setSelected(true);
                field.setText("");
            });
            assertThat(indicator.isVisible()).as("hidden when input is blank").isFalse();

            // Enter a valid pattern again → visible ✓
            runEdt(() -> field.setText("^foo$"));
            assertThat(indicator.isVisible()).as("visible when input present and regex on").isTrue();
            assertThat(indicator.getText()).as("valid again shows ✓").isEqualTo("✓");

            // Flip case toggle (should not affect compilation success, but should refresh without error)
            runEdt(() -> caseToggle.setSelected(true));
            assertThat(indicator.getText()).as("still ✓ after case toggle").isEqualTo("✓");
        }
    }

    /* ----------------------------- helpers ----------------------------- */

    private static void runEdt(Runnable action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeAndWait(action);
        }
    }
}
