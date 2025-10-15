package ai.attackframework.tools.burp.ui.primitives;

import ai.attackframework.tools.burp.ui.StatusPanel;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import javax.swing.JTextArea;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies StatusPanel configuration and size clamping.
 */
class StatusPanelTest {

    @Test
    void setStatus_sets_rows_cols_and_makes_wrapper_visible() {
        JTextArea ta = new JTextArea();
        JPanel wrapper = new JPanel();

        StatusPanel.configureTextArea(ta);
        assertThat(ta.isEditable()).isFalse();

        // One line
        StatusPanel.setStatus(ta, wrapper, "line1", 20, 200);
        assertThat(wrapper.isVisible()).isTrue();
        assertThat(ta.getRows()).isEqualTo(1);

        // Three lines -> rows = 3
        String msg = "a\nb\nc";
        StatusPanel.setStatus(ta, wrapper, msg, 20, 200);
        assertThat(ta.getRows()).isEqualTo(3);

        // Clamp max cols (very long line)
        String longLine = "x".repeat(500);
        StatusPanel.setStatus(ta, wrapper, longLine, 20, 60);
        assertThat(ta.getColumns()).isEqualTo(60);

        // Clamp min cols (very short line)
        StatusPanel.setStatus(ta, wrapper, "s", 20, 200);
        assertThat(ta.getColumns()).isEqualTo(20);
    }
}
