package ai.attackframework.tools.burp.ui.text;

import org.junit.jupiter.api.Test;

import javax.swing.JTextArea;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter.Highlight;
import javax.swing.text.Highlighter.HighlightPainter;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link HighlighterManager}.
 *
 * <p>Confirms that:</p>
 * <ul>
 *   <li>{@link HighlighterManager#apply(java.util.List)} adds highlight tags for valid ranges.</li>
 *   <li>{@link HighlighterManager#clear()} removes previously added tags and is idempotent.</li>
 *   <li>Best-effort semantics: invalid ranges are ignored without throwing.</li>
 * </ul>
 *
 * <p>All assertions filter by the painter supplied to the manager; some Look &amp; Feels may add
 * their own internal highlights unrelated to this test.</p>
 */
class HighlighterManagerTest {

    @Test
    void apply_and_clear_highlights_safely() {
        // Arrange a simple text component and a dedicated painter we can identify.
        JTextArea area = new JTextArea("alpha beta gamma");
        HighlightPainter painter =
                new DefaultHighlighter.DefaultHighlightPainter(area.getSelectionColor());
        HighlighterManager mgr = new HighlighterManager(area, painter);

        // Apply two valid ranges: "alpha" and "beta"
        List<int[]> ranges = List.of(new int[]{0, 5}, new int[]{6, 10});
        List<Object> tags = mgr.apply(ranges);
        assertThat(tags).hasSize(2);
        assertThat(countWithPainter(area, painter))
                .as("two painter highlights present")
                .isEqualTo(2);

        // Apply inputs the manager is guaranteed to ignore (null and wrong-length arrays)
        // Use Arrays.asList(...) instead of List.of(...) because List.of disallows null elements.
        List<Object> tags2 = mgr.apply(Arrays.asList(null, new int[]{42}));
        assertThat(tags2).isEmpty();
        assertThat(countWithPainter(area, painter))
                .as("still two painter highlights present")
                .isEqualTo(2);

        // Clear removes our painter highlights
        mgr.clear();
        assertThat(countWithPainter(area, painter))
                .as("no painter highlights after clear")
                .isZero();

        // Double-clear remains safe/idempotent
        mgr.clear();
        assertThat(countWithPainter(area, painter))
                .as("still none after second clear")
                .isZero();

        // Re-apply after document change
        area.setText("foo bar");
        List<Object> tags3 = mgr.apply(List.of(new int[]{0, 3})); // "foo"
        assertThat(tags3).hasSize(1);
        assertThat(countWithPainter(area, painter))
                .as("one painter highlight after re-apply")
                .isEqualTo(1);
    }

    /* ----------------------------- helpers ----------------------------- */

    /**
     * Count only highlights created with the given painter.
     */
    private static int countWithPainter(JTextArea area, HighlightPainter painter) {
        int count = 0;
        for (Highlight h : area.getHighlighter().getHighlights()) {
            if (h.getPainter() == painter) {
                count++;
            }
        }
        return count;
    }
}
