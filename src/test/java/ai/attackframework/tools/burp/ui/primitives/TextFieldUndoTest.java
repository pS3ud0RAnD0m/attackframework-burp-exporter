package ai.attackframework.tools.burp.ui.primitives;

import org.junit.jupiter.api.Test;

import javax.swing.AbstractAction;
import javax.swing.SwingUtilities;
import javax.swing.JTextField;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that Undo/Redo bindings are installed and functional.
 * All document edits and action invocations occur on the EDT.
 */
class TextFieldUndoTest {

    @Test
    void undo_redo_keymap_actions_modify_text() throws Exception {
        JTextField tf = new JTextField();

        SwingUtilities.invokeAndWait(() -> {
            TextFieldUndo.install(tf);

            // First edit via document insert
            Document d = tf.getDocument();
            try {
                d.insertString(0, "first", null);
            } catch (BadLocationException e) {
                throw new RuntimeException(e);
            }

            // Second edit via setText (produces remove+insert in many JDKs)
            tf.setText("second");

            AbstractAction undo = (AbstractAction) tf.getActionMap().get("undo");
            AbstractAction redo = (AbstractAction) tf.getActionMap().get("redo");

            // Two undos -> back to "first"
            undo.actionPerformed(null);  // undo insert("second") -> ""
            undo.actionPerformed(null);  // undo remove("first")  -> "first"
            assertThat(tf.getText()).isEqualTo("first");

            // Two redos -> forward to "second"
            redo.actionPerformed(null);  // redo remove("first")  -> ""
            redo.actionPerformed(null);  // redo insert("second")-> "second"
            assertThat(tf.getText()).isEqualTo("second");
        });
    }
}
