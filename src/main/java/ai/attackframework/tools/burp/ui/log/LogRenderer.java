package ai.attackframework.tools.burp.ui.log;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.swing.text.AbstractDocument;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import ai.attackframework.tools.burp.utils.Logger;

/**
 * Renderer: writes/replaces lines in the document, formats output, and autoscrolls.
 * Uses plain text (no per-level styling) so the log can use JTextArea with line wrap.
 *
 * <p><strong>Threading:</strong> expected on the EDT.</p>
 */
public final class LogRenderer {

    @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "LogRenderer intentionally holds the provided text component as a UI peer; it is never re-exposed.")
    private final JTextComponent textComponent;
    private final Document doc;

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private int lastLineStart = 0;
    private int lastLineLen   = 0;

    /**
     * Creates a renderer bound to the provided text component (e.g. JTextArea for line wrap).
     *
     * <p>Caller must construct on the EDT.</p>
     *
     * @param textComponent target component to render into (must have an AbstractDocument)
     */
    public LogRenderer(JTextComponent textComponent) {
        this.textComponent = textComponent;
        this.doc = textComponent.getDocument();
    }

    /**
     * Clears all rendered content and resets internal cursor state.
     *
     * <p>EDT only.</p>
     */
    public void clear() {
        try {
            if (doc instanceof AbstractDocument ad) {
                ad.remove(0, doc.getLength());
            }
            lastLineStart = 0;
            lastLineLen = 0;
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.clear: " + ex);
        }
    }

    /**
     * Appends a formatted line to the document.
     *
     * @param line  text to append (should include trailing newline)
     * @param level log level (unused; kept for API compatibility)
     */
    public void append(String line, LogStore.Level level) {
        try {
            if (doc instanceof AbstractDocument ad) {
                int start = doc.getLength();
                ad.insertString(start, line, null);
                lastLineStart = start;
                lastLineLen = line.length();
            }
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.append: " + ex);
        }
    }

    /**
     * Replaces the most recently written line, preserving cursor bookkeeping.
     *
     * @param line  replacement text (should include trailing newline)
     * @param level log level (unused; kept for API compatibility)
     */
    public void replaceLast(String line, LogStore.Level level) {
        try {
            if (doc instanceof AbstractDocument ad) {
                ad.remove(lastLineStart, lastLineLen);
                ad.insertString(lastLineStart, line, null);
                lastLineLen = line.length();
            }
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.replaceLast: " + ex);
        }
    }

    /**
     * Scrolls to the bottom unless paused.
     */
    public void autoscrollIfNeeded(boolean paused) {
        if (!paused) textComponent.setCaretPosition(doc.getLength());
    }

    /**
     * Formats a log entry into a single rendered line.
     *
     * <p>
     * @param ts      timestamp (fallbacks to now when null)
     * @param lvl     log level
     * @param msg     log message (nullable)
     * @param repeats duplicate count; {@code >1} renders as {@code (xN)}
     * @return formatted line including trailing newline
     */
    public String formatLine(LocalDateTime ts, LogStore.Level lvl, String msg, int repeats) {
        String timestamp = "[" + TS.format(ts == null ? LocalDateTime.now() : ts) + "]";
        String base = String.format("%s [%s] %s", timestamp, lvl.name(), msg == null ? "" : msg);
        return repeats > 1 ? base + "  (x" + repeats + ")\n" : base + "\n";
    }

}
