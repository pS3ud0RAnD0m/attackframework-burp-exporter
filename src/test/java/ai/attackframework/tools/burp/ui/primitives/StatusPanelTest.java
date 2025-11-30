package ai.attackframework.tools.burp.ui.primitives;

import ai.attackframework.tools.burp.ui.primitives.StatusViews;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import javax.swing.JTextArea;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies {@link StatusViews} configuration and size clamping.
 */
class StatusPanelTest {

    @Test
    void setStatus_sets_rows_cols_and_makes_wrapper_visible() {
        JTextArea ta = new JTextArea();
        JPanel wrapper = new JPanel();

        StatusViews.configureTextArea(ta);
        assertThat(ta.isEditable()).isFalse();

        // One line
        StatusViews.setStatus(ta, wrapper, "line1", 20, 200);
        assertThat(wrapper.isVisible()).isTrue();
        assertThat(ta.getRows()).isEqualTo(1);

        // Three lines -> rows = 3
        String msg = "a\nb\nc";
        StatusViews.setStatus(ta, wrapper, msg, 20, 200);
        assertThat(ta.getRows()).isEqualTo(3);

        // Clamp max cols (very long line)
        String longLine = "x".repeat(500);
        StatusViews.setStatus(ta, wrapper, longLine, 20, 60);
        assertThat(ta.getColumns()).isEqualTo(60);

        // Clamp min cols (very short line)
        StatusViews.setStatus(ta, wrapper, "s", 20, 200);
        assertThat(ta.getColumns()).isEqualTo(20);
    }
}
