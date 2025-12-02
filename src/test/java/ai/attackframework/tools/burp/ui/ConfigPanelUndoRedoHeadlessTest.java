package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.swing.Action;
import javax.swing.InputMap;
import javax.swing.JComponent;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless verification of Undo/Redo bindings and behavior in text fields.
 * <p>
 * Goals:
 *  - Confirm Ctrl/Meta variants (incl. Shift+Z redo) are bound in InputMap.
 *  - Exercise "undo"/"redo" actions directly and assert they mutate text as expected.
 * <p>
 * Notes:
 *  - We call field actions (not physical key events) to stay headless-safe.
 *  - We use replaceSelection(...) to create a single UndoableEdit,
 *    so one undo returns to the original text and one redo reapplies the change.
 */
@Tag("headless")
class ConfigPanelUndoRedoHeadlessTest {

    @Test
    void filePathField_undoRedo_bindings_and_actions() throws Exception {
        ConfigPanel panel = new ConfigPanel();
        JTextField field = (JTextField) getPrivate(panel, "filePathField");

        // 1) Verify key bindings exist (Ctrl and Meta variants, plus Shift+Z redo)
        InputMap im = field.getInputMap(JComponent.WHEN_FOCUSED);
        assertEquals("undo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK)));
        assertEquals("undo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.META_DOWN_MASK)));
        assertEquals("redo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Y, KeyEvent.CTRL_DOWN_MASK)));
        assertEquals("redo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Y, KeyEvent.META_DOWN_MASK)));
        assertEquals("redo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK)));
        assertEquals("redo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.META_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK)));

        // 2) Exercise actions directly using a single-edit change (replaceSelection)
        String original = field.getText();
        onEdtAndWait(() -> {
            field.setCaretPosition(field.getText().length());
            field.replaceSelection("X"); // single UndoableEdit
        });

        Action undo = field.getActionMap().get("undo");
        assertNotNull(undo, "undo action should be installed");
        onEdtAndWait(() -> undo.actionPerformed(new ActionEvent(field, ActionEvent.ACTION_PERFORMED, "undo")));
        assertEquals(original, field.getText(), "Undo should restore original text");

        Action redo = field.getActionMap().get("redo");
        assertNotNull(redo, "redo action should be installed");
        onEdtAndWait(() -> redo.actionPerformed(new ActionEvent(field, ActionEvent.ACTION_PERFORMED, "redo")));
        assertEquals(original + "X", field.getText(), "Redo should re-apply the change");
    }

    @Test
    void openSearchUrlField_undoRedo_bindings_and_actions() throws Exception {
        ConfigPanel panel = new ConfigPanel();
        JTextField field = (JTextField) getPrivate(panel, "openSearchUrlField");

        // 1) Verify key bindings exist (Ctrl and Meta variants, plus Shift+Z redo)
        InputMap im = field.getInputMap(JComponent.WHEN_FOCUSED);
        assertEquals("undo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK)));
        assertEquals("undo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.META_DOWN_MASK)));
        assertEquals("redo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Y, KeyEvent.CTRL_DOWN_MASK)));
        assertEquals("redo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Y, KeyEvent.META_DOWN_MASK)));
        assertEquals("redo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK)));
        assertEquals("redo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.META_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK)));

        // 2) Exercise actions directly using a single-edit change (replaceSelection)
        String original = field.getText();
        onEdtAndWait(() -> {
            field.setCaretPosition(field.getText().length());
            field.replaceSelection("/extra"); // single UndoableEdit
        });

        Action undo = field.getActionMap().get("undo");
        assertNotNull(undo, "undo action should be installed");
        onEdtAndWait(() -> undo.actionPerformed(new ActionEvent(field, ActionEvent.ACTION_PERFORMED, "undo")));
        assertEquals(original, field.getText(), "Undo should restore original text");

        Action redo = field.getActionMap().get("redo");
        assertNotNull(redo, "redo action should be installed");
        onEdtAndWait(() -> redo.actionPerformed(new ActionEvent(field, ActionEvent.ACTION_PERFORMED, "redo")));
        assertEquals(original + "/extra", field.getText(), "Redo should re-apply the change");
    }

    // ---------- helpers ----------

    /** Small reflection helper for private UI fields—keeps tests focused on behavior, not wiring. */
    private static Object getPrivate(Object target, String fieldName) throws Exception {
        var f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return f.get(target);
    }

    /** Run a block on the EDT and wait for completion (avoids subtle race conditions). */
    private static void onEdtAndWait(Runnable r) throws Exception {
        if (javax.swing.SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            javax.swing.SwingUtilities.invokeAndWait(r);
        }
    }
}
