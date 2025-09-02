package ai.attackframework.tools.burp.ui.text;

import javax.swing.text.BadLocationException;
import javax.swing.text.Highlighter;
import javax.swing.text.JTextComponent;
import javax.swing.text.Highlighter.HighlightPainter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Manages highlight tags on a {@link JTextComponent}.
 *
 * <h3>Contract</h3>
 * <ul>
 *   <li>{@link #apply(List)} adds highlights for the given half-open ranges and remembers the tags.</li>
 *   <li>{@link #clear()} removes previously added tags; safe to call repeatedly.</li>
 *   <li>Best-effort semantics: invalid offsets during rapid edits are ignored.</li>
 * </ul>
 *
 * <p>This class does not perform any EDT enforcement; callers should update from the EDT.</p>
 */
public final class HighlighterManager {

    private final JTextComponent component;
    private final HighlightPainter painter;
    private final List<Object> tags = new ArrayList<>();

    /**
     * @param component the target text component (required)
     * @param painter   the painter to use for new highlights (required)
     * @throws NullPointerException if any required argument is {@code null}
     */
    public HighlighterManager(JTextComponent component, HighlightPainter painter) {
        this.component = Objects.requireNonNull(component, "component");
        this.painter = Objects.requireNonNull(painter, "painter");
    }

    /**
     * Apply highlights for the given ranges.
     *
     * @param ranges list of {@code [start, end]} pairs in component coordinates
     * @return list of created highlight tags (useful if the caller wants its own bookkeeping)
     */
    public List<Object> apply(List<int[]> ranges) {
        final Highlighter h = component.getHighlighter();
        final List<Object> created = new ArrayList<>();
        if (ranges == null || ranges.isEmpty()) return created;

        for (int[] r : ranges) {
            if (r == null || r.length != 2) continue;
            try {
                Object tag = h.addHighlight(r[0], r[1], painter);
                tags.add(tag);
                created.add(tag);
            } catch (BadLocationException | RuntimeException ignore) {
                // Best-effort: offsets/tags may be invalid if the document mutated concurrently.
            }
        }
        return created;
    }

    /**
     * Remove previously created highlights. Safe to call multiple times.
     */
    public void clear() {
        final Highlighter h = component.getHighlighter();
        for (Object tag : tags) {
            try {
                h.removeHighlight(tag);
            } catch (RuntimeException ignore) {
                // Tag may be stale if the document mutated; removal is best-effort.
            }
        }
        tags.clear();
    }
}
