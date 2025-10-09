package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JTextPane;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Document rendering operations.
 *
 * <p>Validates append/replace behavior, formatted output, and caret movement
 * when autoscroll is not paused.</p>
 */
class LogRendererAppendReplaceTest {

    /**
     * Appending then replacing the last line updates the document text,
     * and autoscroll moves the caret to the end.
     */
    @Test
    void append_then_replaceLast_updates_document_and_autoscroll_moves_caret() throws Exception {
        JTextPane pane = new JTextPane();
        LogRenderer r = new LogRenderer(pane);

        String line1 = r.formatLine(java.time.LocalDateTime.now(), LogStore.Level.INFO, "one", 1);
        String line2 = r.formatLine(java.time.LocalDateTime.now(), LogStore.Level.ERROR, "two", 3);

        r.append(line1, LogStore.Level.INFO);
        assertEquals(line1, pane.getDocument().getText(0, pane.getDocument().getLength()));

        r.replaceLast(line2, LogStore.Level.ERROR);
        assertEquals(line2, pane.getDocument().getText(0, pane.getDocument().getLength()));

        r.autoscrollIfNeeded(false);
        assertEquals(pane.getDocument().getLength(), pane.getCaretPosition());
    }
}
