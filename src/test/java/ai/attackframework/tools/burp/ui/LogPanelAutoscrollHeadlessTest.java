package ai.attackframework.tools.burp.ui;

import java.awt.Point;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.Reflect;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.allText;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.field;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.newPanel;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.onEdt;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.realize;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.resetPanelState;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.searchCountText;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.setPaused;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.setText;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.setViewportY;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.textPane;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.viewportPosition;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.waitFor;
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

    @Test
    void autoscroll_paused_append_preservesViewport() {
        LogPanel p = newPanel();
        resetPanelState(p);
        realize(p);
        appendSeedLines(p);
        setPaused(p, true);
        setViewportY(p, 80);
        Point before = viewportPosition(p);

        onEdt(() -> p.onLog("INFO", "new visible tail line"));

        waitFor(() -> allText(p).contains("new visible tail line"), 1500);
        assertThat(viewportPosition(p)).isEqualTo(before);
    }

    @Test
    void autoscroll_paused_duplicateReplacement_preservesViewport_andUpdatesCount() {
        LogPanel p = newPanel();
        resetPanelState(p);
        realize(p);
        appendSeedLines(p);
        onEdt(() -> p.onLog("INFO", "repeat target"));
        setPaused(p, true);
        setViewportY(p, 80);
        Point before = viewportPosition(p);

        onEdt(() -> p.onLog("INFO", "repeat target"));

        waitFor(() -> allText(p).contains("repeat target  (x2)"), 1500);
        assertThat(viewportPosition(p)).isEqualTo(before);
    }

    @Test
    void autoscroll_paused_rebuildView_preservesViewport() {
        LogPanel p = newPanel();
        resetPanelState(p);
        realize(p);
        appendSeedLines(p);
        setPaused(p, true);
        setViewportY(p, 80);
        Point before = viewportPosition(p);

        setText(field(p, "log.filter.text"), "seed line");

        waitFor(() -> allText(p).contains("seed line 119"), 1500);
        assertThat(viewportPosition(p)).isEqualTo(before);
    }

    @Test
    void autoscroll_paused_searchRecompute_doesNotRevealNewMatch() {
        LogPanel p = newPanel();
        resetPanelState(p);
        realize(p);
        appendSeedLines(p);
        onEdt(() -> p.onLog("INFO", "needle baseline"));
        setText(field(p, "log.search.field"), "needle");
        setPaused(p, true);
        setViewportY(p, 80);
        Point before = viewportPosition(p);

        onEdt(() -> p.onLog("INFO", "needle appended"));

        waitFor(() -> "1/2".equals(searchCountText(p)), 1500);
        assertThat(viewportPosition(p)).isEqualTo(before);
    }

    @Test
    void hiddenView_ingestsWithoutDocumentChurn() {
        LogPanel p = newPanel();
        resetPanelState(p);
        realize(p);
        appendSeedLines(p);
        String before = allText(p);

        Reflect.set(p, "viewActive", false);
        Reflect.set(p, "viewDirty", false);
        onEdt(() -> p.onLog("INFO", "hidden line"));

        assertThat(allText(p)).isEqualTo(before);
        assertThat(Reflect.get(p, "viewDirty", Boolean.class)).isTrue();
    }

    private static void appendSeedLines(LogPanel p) {
        onEdt(() -> {
            for (int i = 0; i < 120; i++) {
                p.onLog("INFO", "seed line " + i);
            }
        });
        waitFor(() -> allText(p).contains("seed line 119"), 1500);
    }
}
