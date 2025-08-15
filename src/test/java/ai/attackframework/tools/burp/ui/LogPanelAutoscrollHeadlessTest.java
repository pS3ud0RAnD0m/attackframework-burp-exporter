package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.newPanel;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.realize;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.resetPanelState;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.setPaused;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.textPane;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.waitFor;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.onEdt;
import static org.assertj.core.api.Assertions.assertThat;

class LogPanelAutoscrollHeadlessTest {

    @Test
    void autoscroll_movesCaret_whenNotPaused() {
        LogPanel p = newPanel();
        resetPanelState(p);
        realize(p);
        setPaused(p, false);

        onEdt(() -> textPane(p).setCaretPosition(0));
        p.onLog("INFO", "moved-to-end");

        waitFor(() -> textPane(p).getDocument().getLength() > 0, 1500);

        int caret = textPane(p).getCaretPosition();
        int len = textPane(p).getDocument().getLength();
        assertThat(caret).isEqualTo(len);
    }

    @Test
    void autoscroll_paused_doesNotMoveCaret() {
        LogPanel p = newPanel();
        resetPanelState(p);
        realize(p);
        setPaused(p, true);

        onEdt(() -> textPane(p).setCaretPosition(0));
        p.onLog("INFO", "kept-in-place");

        waitFor(() -> textPane(p).getDocument().getLength() > 0, 1500);

        int caret = textPane(p).getCaretPosition();
        int len = textPane(p).getDocument().getLength();
        assertThat(caret).isLessThan(len);
    }
}
