package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import org.junit.jupiter.api.Test;

import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Container;
import java.io.*;
import java.lang.reflect.Field;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates that a restored {@link ConfigPanel} recreates its transient controller
 * and that a save operation updates the admin status area.
 */
class ConfigPanelSerializationHeadlessTest {

    @Test
    void controller_is_transient_and_fresh_panel_saves() throws Exception {
        ConfigPanel original = new ConfigPanel(new ConfigController(new SilentUi()));

        byte[] bytes = serialize(original);
        ConfigPanel restored = (ConfigPanel) deserialize(bytes);

        realize(restored);

        // Locate the wrapper by name; the text area may be created when status is first posted.
        Container wrapper = (Container) findByName(restored, "admin.statusWrapper");
        assertThat(wrapper).as("the admin status wrapper").isNotNull();

        // Drive Save through the fresh controller on the restored panel.
        ConfigController ctrl = controllerOf(restored);
        ConfigState.State state = new ConfigState.State(
                List.of(), ConfigKeys.SCOPE_ALL, List.of(), new ConfigState.Sinks(false, null, false, null)
        );
        ctrl.saveAsync(state);

        // Await the creation and population of the admin text area.
        AtomicReference<JTextArea> areaRef = new AtomicReference<>();
        await(() -> {
            JTextArea ta = (JTextArea) findFirst(wrapper, JTextArea.class);
            if (ta == null) return false;
            areaRef.set(ta);
            String txt = ta.getText();
            return txt != null && !txt.isBlank();
        });

        JTextArea adminArea = areaRef.get();
        assertThat(adminArea).as("the admin status area").isNotNull();
        assertThat(adminArea.getText()).isNotBlank();
    }

    // ---- helpers ----

    private static byte[] serialize(Serializable obj) throws IOException {
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bout)) {
            out.writeObject(obj);
            return bout.toByteArray();
        }
    }

    private static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bin = new ByteArrayInputStream(bytes);
             ObjectInputStream in = new ObjectInputStream(bin)) {
            return in.readObject();
        }
    }

    /** Sizes and lays out the panel so component lookups are reliable in headless mode. */
    private static void realize(ConfigPanel p) {
        if (p.getWidth() <= 0 || p.getHeight() <= 0) {
            p.setSize(1000, 700);
        }
        p.doLayout();
    }

    /** Extracts the controller restored in readObject(...) on the panel. */
    private static ConfigController controllerOf(ConfigPanel p) throws Exception {
        Field f = ConfigPanel.class.getDeclaredField("controller");
        f.setAccessible(true);
        return (ConfigController) f.get(p);
    }

    private static Component findByName(Container root, String name) {
        if (name.equals(root.getName())) return root;
        for (Component c : root.getComponents()) {
            if (name.equals(c.getName())) return c;
            if (c instanceof Container child) {
                Component hit = findByName(child, name);
                if (hit != null) return hit;
            }
        }
        return null;
    }

    /** Depth-first search for the first descendant of the requested type. */
    private static Component findFirst(Container root, Class<?> type) {
        for (Component c : root.getComponents()) {
            if (type.isInstance(c)) return c;
            if (c instanceof Container child) {
                Component hit = findFirst(child, type);
                if (hit != null) return hit;
            }
        }
        return null;
    }

    /** Bounded await helper using short parks (no Thread.sleep in loops). */
    private static void await(Callable<Boolean> cond) throws Exception {
        final long deadline = System.currentTimeMillis() + 3000;
        while (System.currentTimeMillis() < deadline) {
            if (Boolean.TRUE.equals(cond.call())) return;
            LockSupport.parkNanos(15_000_000L); // ~15ms
        }
        throw new AssertionError("Timed out while waiting for admin status text");
    }

    /** Silent Ui for the original panel; restored panel uses its own controller to post status. */
    private static final class SilentUi implements ConfigController.Ui, Serializable {
        @Serial private static final long serialVersionUID = 1L;
        @Override public void onFileStatus(String message) { /* not used */ }
        @Override public void onOpenSearchStatus(String message) { /* not used */ }
        @Override public void onAdminStatus(String message) { /* not used */ }
    }
}
