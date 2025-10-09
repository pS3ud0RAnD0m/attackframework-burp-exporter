package ai.attackframework.tools.burp.ui.text;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Non-brittle check that the indicator's preferred width does not shrink when toggling
 * between ✓ and ✖, which would cause visual jitter.
 */
class RegexIndicatorBinderWidthHeadlessTest {

    @Test
    void preferred_width_is_stable_between_glyphs() throws Exception {
        runEdt(() -> {
            JTextField field = new JTextField();
            JCheckBox regex = new JCheckBox();
            JCheckBox cs = new JCheckBox();
            JLabel indicator = new JLabel();

            try (AutoCloseable ignored = RegexIndicatorBinder.bind(field, regex, cs, /*multiline*/ false, indicator)) {
                // show ✓
                regex.setSelected(true);
                field.setText("foo");
                cs.setSelected(true); // case-sensitive; still valid
                flushEdt();

                int widthForCheck = indicator.getPreferredSize().width;
                assertThat(widthForCheck).isGreaterThan(0);

                // show ✖
                field.setText("[unterminated");
                flushEdt();

                int widthForX = indicator.getPreferredSize().width;
                assertThat(widthForX).isGreaterThanOrEqualTo(widthForCheck);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    /* ----------------------------- helpers ----------------------------- */

    private static void runEdt(Runnable action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeAndWait(action);
        }
    }

    private static void flushEdt() throws Exception {
        runEdt(() -> {});
    }
}
