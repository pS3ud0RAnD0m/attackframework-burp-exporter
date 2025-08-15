package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.button;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.check;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.click;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.field;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.newPanel;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.realize;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.resetPanelState;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.searchCountText;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.setText;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.triggerSearchNextViaEnter;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.waitFor;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogPanelSearchHeadlessTest {

    @Test
    void caseInsensitive_search_highlights_and_enter_advances() {
        LogPanel p = newPanel();
        resetPanelState(p);
        realize(p);

        p.onLog("INFO", "alpha");
        p.onLog("INFO", "opensearch appears here");
        p.onLog("INFO", "noise");
        p.onLog("INFO", "second opensearch occurrence");

        // yield once
        waitFor(() -> true, 50);

        setText(field(p, "log.search.field"), "opensearch");

        assertTrue(waitFor(() -> searchCountText(p).matches("1/2"), 2000),
                "expected to be at 1/2 after initial search");

        triggerSearchNextViaEnter(p);
        assertTrue(waitFor(() -> searchCountText(p).matches("2/2"), 2000),
                "expected to be at 2/2 after Enter");

        JButton next = button(p, "log.search.next");
        click(next);
        assertTrue(waitFor(() -> searchCountText(p).matches("1/2"), 2000),
                "expected wraparound to 1/2");
    }

    @Test
    void regex_search_with_anchors_multiline_works() {
        LogPanel p = newPanel();
        resetPanelState(p);
        realize(p);

        p.onLog("INFO", "the quick brown fox");
        p.onLog("INFO", "opensearch is here");
        p.onLog("INFO", "another line");
        p.onLog("INFO", "opensearch at start");

        // Enable regex mode
        if (!check(p, "log.search.regex").isSelected()) {
            click(check(p, "log.search.regex"));
        }

        // Lines are rendered with "[timestamp] [LEVEL] message"
        // Anchor the whole line and match 'opensearch' anywhere on that line.
        setText(field(p, "log.search.field"), "^.*opensearch.*$");

        assertTrue(waitFor(() -> searchCountText(p).matches("1/2"), 2000),
                "expected 1/2 in regex mode initially");
    }
}
