package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.util.List;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Headless smoke test for the first-row scope indicator wiring in {@link ConfigPanel}.
 *
 * <p>Asserts that:</p>
 * <ul>
 *   <li>When regex mode is enabled and the first field contains an invalid pattern,
 *       the indicator shows {@code ✖} and is visible.</li>
 *   <li>When regex mode is disabled, the indicator hides.</li>
 * </ul>
 *
 * <p>All UI actions are followed by an EDT flush to ensure listener side effects
 * are applied before assertions.</p>
 */
class ConfigPanelScopeIndicatorHeadlessTest {

    @Test
    void first_row_indicator_shows_cross_for_invalid_and_hides_when_off() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        // Access first-row components through existing private fields.
        JTextField field = get(panel, "customScopeField");

        List<JCheckBox> toggles = get(panel, "customScopeRegexToggles");
        JCheckBox regexToggle = toggles.getFirst();

        List<JLabel> indicators = get(panel, "customScopeIndicators");
        JLabel indicator = indicators.getFirst();

        // Turn regex ON, then enter an invalid pattern -> expect ✖ and visible
        runEdt(() -> {
            regexToggle.setSelected(true);           // programmatic toggle (ItemEvent)
            field.setText("[unterminated");          // invalid regex (DocumentEvent)
        });
        assertThat(indicator.isVisible()).as("indicator visible when regex is on").isTrue();
        assertThat(indicator.getText()).as("invalid regex shows ✖").isEqualTo("✖");

        // Turn regex OFF -> indicator hides
        runEdt(() -> regexToggle.setSelected(false));
        assertThat(indicator.isVisible()).as("indicator hides when regex mode is off").isFalse();
    }

    /* ----------------------------- helpers ----------------------------- */

    /** Run the given action on the EDT and block until it completes. */
    private static void runEdt(Runnable action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeAndWait(action);
        }
    }
}
