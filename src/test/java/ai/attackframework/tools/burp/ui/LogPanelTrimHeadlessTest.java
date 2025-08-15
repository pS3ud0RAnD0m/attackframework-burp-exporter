package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies duplicate-compaction renders "(xN)" on consecutive identical messages.
 */
class LogPanelTrimHeadlessTest {

    @Test
    void consecutiveDuplicates_compactWithCount() {
        LogPanel p = newPanel();

        p.onLog("INFO", "same");
        p.onLog("INFO", "same");
        p.onLog("INFO", "same");

        String text = allText(p);
        assertThat(text).contains("(x3)");
        // only one visual line for the compacted sequence
        assertThat(text).containsSubsequence("same");
        assertThat(text.indexOf("same")).isEqualTo(text.lastIndexOf("same"));
    }
}
