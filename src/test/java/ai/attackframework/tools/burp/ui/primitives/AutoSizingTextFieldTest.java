package ai.attackframework.tools.burp.ui.primitives;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ensures preferred size tracks content length within clamps.
 */
class AutoSizingTextFieldTest {

    @Test
    void preferred_width_tracks_text_within_min_max() {
        AutoSizingTextField tf = new AutoSizingTextField("");

        int wEmpty = tf.getPreferredSize().width;
        tf.setText("12345678901234567890"); // 20 chars
        int w20 = tf.getPreferredSize().width;
        tf.setText("x".repeat(500));        // very long
        int wLong = tf.getPreferredSize().width;

        assertThat(w20)
                .as("width grows from empty to 20 chars")
                .isGreaterThan(wEmpty);
        assertThat(wLong)
                .as("width grows from 20 chars to very long, clamped at 900")
                .isGreaterThan(w20)
                .isLessThanOrEqualTo(900);

        AutoSizingTextField tf2 = new AutoSizingTextField("a");
        assertThat(tf2.getPreferredSize().width)
                .as("lower bound is at least 80")
                .isGreaterThanOrEqualTo(80);
    }
}
