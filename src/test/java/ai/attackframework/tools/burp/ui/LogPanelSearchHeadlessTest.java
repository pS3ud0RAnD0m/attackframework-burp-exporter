package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.Logger;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Focused tests for LogPanel search:
 * - default is case-insensitive substring matching
 * - Enter in the search field advances to the next match
 * - regex mode works with ^/$ anchors (MULTILINE)
 */
class LogPanelSearchHeadlessTest extends LogPanelTestHarness {

    @Test
    void caseInsensitive_search_highlights_and_enter_advances() {
        LogPanel p = newPanelOnEdt();

        // Emit a few lines
        Logger.logInfo("alpha opensearch bravo");
        Logger.logInfo("ALPHA OPENSEARCH BRAVO");
        Logger.logInfo("no match here");

        JTextField search = field(p, "log.search.field");

        // Type 'opensearch' (default: case-insensitive, non-regex)
        setText(search, "opensearch");

        // Wait until matches are computed; expect 2 total and we're on the 1st hit (1/2)
        assertTrue(waitFor(() -> searchCountText(p).matches("1/2"), 2000),
                "expected to be at 1/2 after initial search");

        // Hitting Enter in the field should trigger "Next" (advance to 2/2)
        triggerSearchNextViaEnter(p);
        assertTrue(waitFor(() -> searchCountText(p).matches("2/2"), 1500),
                "expected to be at 2/2 after Enter");

        // Clicking Next again should wrap to 1/2
        JButton next = button(p, "log.search.next");
        click(next);
        assertTrue(waitFor(() -> searchCountText(p).matches("1/2"), 1500),
                "expected wraparound to 1/2");
    }

    @Test
    void regex_search_with_anchors_multiline_works() {
        LogPanel p = newPanelOnEdt();

        // Emit lines, ensure only two contain "opensearch"
        Logger.logInfo("the quick brown fox");
        Logger.logInfo("opensearch in this line");
        Logger.logInfo("another OPENSEARCH sample");
        Logger.logInfo("final line without the token");

        // Toggle REGEX mode via tooltip (component may not have a name)
        JCheckBox regexToggle = check(p, "Regex search");
        click(regexToggle);

        // Enter a regex that matches whole lines containing 'opensearch' (case-insensitive by default in regex mode)
        JTextField search = field(p, "log.search.field");
        setText(search, "^.*opensearch.*$");

        // Expect 2 total matches; first should be focused (1/2)
        assertTrue(waitFor(() -> searchCountText(p).matches("1/2"), 2000),
                "expected 1/2 in regex mode initially");

        // Go to next => 2/2
        JButton next = button(p, "log.search.next");
        click(next);
        assertTrue(waitFor(() -> searchCountText(p).matches("2/2"), 1500),
                "expected 2/2 after next");

        // Verify the match count label is detectable by the harness pattern
        assertNotNull(labelMatching(p, Pattern.compile("\\d+/\\d+")));
    }
}
