package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.testutils.Reflect;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static java.lang.reflect.Modifier.isTransient;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the controller field is transient and that a fresh instance
 * (which is what deserialization restores via {@code readObject}) still supports Save.
 */
class ConfigPanelSerializationHeadlessTest {

    @Test
    void controller_is_transient_and_fresh_panel_saves() throws Exception {
        // Field is transient
        Field f = ConfigPanel.class.getDeclaredField("controller");
        assertThat(isTransient(f.getModifiers())).as("controller field is transient").isTrue();

        // Fresh instance behaves as expected (post-deserialization invariant)
        ConfigPanel restored = new ConfigPanel();

        Object controller = Reflect.get(restored, "controller");
        assertThat(controller).isInstanceOf(ConfigController.class);

        // Click Save
        JButton saveBtn = findSaveButton(restored);
        assertThat(saveBtn).as("Save button").isNotNull();
        saveBtn.doClick();

        // Find a JTextArea whose text is exactly "Saved!"
        JTextArea admin = findSavedStatusArea(restored);
        assertThat(admin).as("admin status area").isNotNull();
        assertThat(admin.getText()).isEqualTo("Saved!");
    }

    /* ---------------- helpers ---------------- */

    private static JButton findSaveButton(JComponent root) {
        List<JButton> all = new ArrayList<>();
        collect(root, JButton.class, all);
        for (JButton b : all) {
            String t = b.getText();
            if (t != null && t.startsWith("Save")) return b;
        }
        return null;
    }

    private static JTextArea findSavedStatusArea(JComponent root) {
        List<JTextArea> all = new ArrayList<>();
        collect(root, JTextArea.class, all);
        for (JTextArea ta : all) {
            String t = ta.getText();
            if ("Saved!".equals(t)) return ta;
        }
        return null;
    }

    private static <T extends JComponent> void collect(JComponent root, Class<T> type, List<T> out) {
        if (type.isInstance(root)) out.add(type.cast(root));
        if (root instanceof JPanel p) {
            for (var comp : p.getComponents()) {
                if (comp instanceof JComponent jc) collect(jc, type, out);
            }
        } else {
            for (var comp : root.getComponents()) {
                if (comp instanceof JComponent jc) collect(jc, type, out);
            }
        }
    }
}
