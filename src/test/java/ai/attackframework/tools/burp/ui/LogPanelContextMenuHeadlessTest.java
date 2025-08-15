package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates context menu composition without invoking system clipboard (headless-safe).
 */
class LogPanelContextMenuHeadlessTest {

    @Test
    void contextMenu_containsExpectedItems_inOrder() {
        LogPanel p = newPanel();
        JPopupMenu menu = buildContextMenuViaReflection(p);

        // Expected items:
        // 0: "Copy selection"
        // 1: "Copy current line"
        // 2: "Copy all"
        // 3: separator
        // 4: "Save visible…"
        assertThat(menu.getComponentCount()).isGreaterThanOrEqualTo(5);

        JMenuItem i0 = (JMenuItem) menu.getComponent(0);
        JMenuItem i1 = (JMenuItem) menu.getComponent(1);
        JMenuItem i2 = (JMenuItem) menu.getComponent(2);
        // index 3 is a JSeparator
        JMenuItem i4 = (JMenuItem) menu.getComponent(4);

        assertThat(i0.getText()).isEqualTo("Copy selection");
        assertThat(i1.getText()).isEqualTo("Copy current line");
        assertThat(i2.getText()).isEqualTo("Copy all");
        assertThat(i4.getText()).isEqualTo("Save visible…");
    }
}
