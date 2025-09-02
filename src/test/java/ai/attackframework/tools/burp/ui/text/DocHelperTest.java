package ai.attackframework.tools.burp.ui.text;

import org.junit.jupiter.api.Test;

import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link Doc#onChange(Runnable)}.
 *
 * <p>Validates that the returned listener invokes its action for text edits:
 * insertions and removals. We do not assert on {@code changedUpdate} here since
 * plain text documents typically do not fire it for content edits.</p>
 */
class DocHelperTest {

    @Test
    void onChange_invokes_action_on_insert_and_remove() throws Exception {
        // Arrange a simple text component and attach the listener
        JTextField field = new JTextField();
        Document doc = field.getDocument();

        AtomicInteger calls = new AtomicInteger(0);
        var listener = Doc.onChange(calls::incrementAndGet);
        runEdt(() -> doc.addDocumentListener(listener));

        // Act + Assert: insert triggers exactly one invocation
        runEdt(() -> insert(doc, 0, "abc"));
        assertThat(calls.get()).as("insert fires once").isEqualTo(1);

        // Another insert increments once more
        runEdt(() -> insert(doc, doc.getLength(), "Z"));
        assertThat(calls.get()).as("second insert fires once more").isEqualTo(2);

        // Removal increments once more
        runEdt(() -> removeFirst(doc));
        assertThat(calls.get()).as("remove fires once more").isEqualTo(3);

        // Cleanup
        runEdt(() -> doc.removeDocumentListener(listener));
    }

    /* ----------------------------- helpers ----------------------------- */

    private static void insert(Document doc, int offset, String text) {
        try {
            doc.insertString(offset, text, null);
        } catch (BadLocationException e) {
            throw new RuntimeException(e);
        }
    }

    /** Remove the first character, if present. */
    private static void removeFirst(Document doc) {
        try {
            if (doc.getLength() > 0) {
                doc.remove(0, 1);
            }
        } catch (BadLocationException e) {
            throw new RuntimeException(e);
        }
    }

    /** Run the given action on the EDT and block until it completes. */
    private static void runEdt(Runnable action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeAndWait(action);
        }
    }
}
