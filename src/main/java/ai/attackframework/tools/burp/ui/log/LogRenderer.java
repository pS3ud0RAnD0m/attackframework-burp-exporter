package ai.attackframework.tools.burp.ui.log;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.swing.JTextPane;
import javax.swing.UIManager;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import ai.attackframework.tools.burp.utils.Logger;

/**
 * Renderer: writes/replaces lines in the document, formats output, and autoscrolls.
 *
 * <p><strong>Threading:</strong> expected on the EDT.</p>
 */
public final class LogRenderer {

    @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "LogRenderer intentionally holds the provided JTextPane as a UI peer; it is never re-exposed.")
    private final JTextPane textPane;
    private final StyledDocument doc;
    private final Style infoStyle;
    private final Style errorStyle;

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private int lastLineStart = 0;
    private int lastLineLen   = 0;

    /**
     * Creates a renderer bound to the provided text pane.
     *
     * <p>Caller must construct on the EDT. The pane is held as a UI peer; styles are initialized
     * with the current Look and Feel.</p>
     *
     * <p>
     * @param textPane target pane to render into
     */
    public LogRenderer(JTextPane textPane) {
        this.textPane = textPane;
        this.doc = textPane.getStyledDocument();

        infoStyle = doc.addStyle("INFO", null);
        StyleConstants.setForeground(infoStyle, UIManager.getColor("TextPane.foreground"));

        errorStyle = doc.addStyle("ERROR", null);
        StyleConstants.setForeground(errorStyle, UIManager.getColor("TextPane.foreground"));
        StyleConstants.setBold(errorStyle, true);
    }

    /**
     * Clears all rendered content and resets internal cursor state.
     *
     * <p>EDT only.</p>
     */
    public void clear() {
        try {
            doc.remove(0, doc.getLength());
            lastLineStart = 0;
            lastLineLen = 0;
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.clear: " + ex);
        }
    }

    /**
     * Appends a formatted line to the document with styling derived from the level.
     *
     * <p>
     * @param line  text to append (should include trailing newline)
     * @param level log level determining style
     */
    public void append(String line, LogStore.Level level) {
        try {
            int start = doc.getLength();
            doc.insertString(start, line, styleFor(level));
            lastLineStart = start;
            lastLineLen = line.length();
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.append: " + ex);
        }
    }

    /**
     * Replaces the most recently written line, preserving cursor bookkeeping.
     *
     * <p>
     * @param line  replacement text (should include trailing newline)
     * @param level log level determining style
     */
    public void replaceLast(String line, LogStore.Level level) {
        try {
            doc.remove(lastLineStart, lastLineLen);
            doc.insertString(lastLineStart, line, styleFor(level));
            lastLineLen = line.length();
        } catch (BadLocationException ex) {
            Logger.internalDebug("LogRenderer.replaceLast: " + ex);
        }
    }

    /**
     * Scrolls to the bottom unless paused.
     *
     * <p>
     * @param paused when true, leaves caret position unchanged
     */
    public void autoscrollIfNeeded(boolean paused) {
        if (!paused) textPane.setCaretPosition(doc.getLength());
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

    /**
     * Resolves the text style for a log level.
     *
     * <p>
     * @param level log level
     * @return Swing style to apply
     */
    private Style styleFor(LogStore.Level level) {
        return (level == LogStore.Level.ERROR) ? errorStyle : infoStyle;
    }
}
