package ai.attackframework.tools.burp.ui;

import java.lang.reflect.Method;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.Logger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ensures LogPanel receives log messages only when in the display hierarchy and gets
 * replayed messages when re-added (regression test for tab-switch / clean-start Log panel
 * missing messages). Invokes addNotify/removeNotify on the EDT to simulate hierarchy
 * lifecycle without requiring a display (headless-safe).
 */
@Tag("headless")
class LogPanelLoggerLifecycleHeadlessTest {

    @Test
    void panel_receivesLogsWhenInHierarchy_getsReplayWhenReAdded() throws Exception {
        LogPanel panel = LogPanelTestHarness.newPanel();

        SwingUtilities.invokeAndWait(() -> invokeAddNotify(panel));
        // Simulates panel added to hierarchy → register with Logger

        SwingUtilities.invokeAndWait(() -> Logger.logInfo("while-visible"));
        String afterFirst = LogPanelTestHarness.allText(panel);
        assertThat(afterFirst).contains("while-visible");

        SwingUtilities.invokeAndWait(() -> invokeRemoveNotify(panel));
        // Simulates panel removed → unregister

        SwingUtilities.invokeAndWait(() -> Logger.logInfo("while-removed"));
        // Panel is not registered so it did not receive "while-removed" yet

        SwingUtilities.invokeAndWait(() -> invokeAddNotify(panel));
        // Re-added → register and replay
        SwingUtilities.invokeAndWait(() -> { /* drain EDT for replay */ });

        String afterReAdd = LogPanelTestHarness.allText(panel);
        assertThat(afterReAdd).contains("while-visible");
        assertThat(afterReAdd).contains("while-removed");
    }

    private static void invokeAddNotify(LogPanel panel) {
        try {
            Method m = java.awt.Component.class.getDeclaredMethod("addNotify");
            m.setAccessible(true);
            m.invoke(panel);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void invokeRemoveNotify(LogPanel panel) {
        try {
            Method m = java.awt.Component.class.getDeclaredMethod("removeNotify");
            m.setAccessible(true);
            m.invoke(panel);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
