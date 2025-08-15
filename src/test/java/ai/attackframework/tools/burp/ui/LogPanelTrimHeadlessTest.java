package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.allText;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.newPanel;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.resetPanelState;
import static org.assertj.core.api.Assertions.assertThat;

class LogPanelTrimHeadlessTest {

    @Test
    void consecutiveDuplicates_compactWithCount() {
        LogPanel p = newPanel();
        resetPanelState(p);

        p.onLog("INFO", "same");
        p.onLog("INFO", "same");
        p.onLog("INFO", "same");

        String text = allText(p);
        assertThat(text).contains("(x3)");
        assertThat(text).containsSubsequence("same");
        assertThat(text.indexOf("same")).isEqualTo(text.lastIndexOf("same"));
    }
}
