package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JTextPane;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.*;
import static org.assertj.core.api.Assertions.assertThat;

class LogPanelAutoscrollHeadlessTest {

    @Test
    void autoscroll_movesCaret_whenNotPaused() {
        LogPanel p = newPanel();
        JCheckBox pause = check(p, "Pause autoscroll");
        if (pause.isSelected()) click(pause); // ensure OFF

        // emit some lines
        p.onLog("INFO", "one");
        p.onLog("INFO", "two");
        p.onLog("INFO", "three");

        JTextPane ed = editor(p);
        int len = ed.getDocument().getLength();
        assertThat(ed.getCaretPosition()).isEqualTo(len);
    }

    @Test
    void autoscroll_stops_whenPaused() {
        LogPanel p = newPanel();
        JCheckBox pause = check(p, "Pause autoscroll");
        if (!pause.isSelected()) click(pause); // turn ON

        // move caret to start, then emit
        editor(p).setCaretPosition(0);
        p.onLog("INFO", "kept-in-place");

        int caret = editor(p).getCaretPosition();
        int len = editor(p).getDocument().getLength();
        // caret should not follow to the end
        assertThat(caret).isLessThan(len);
    }
}
