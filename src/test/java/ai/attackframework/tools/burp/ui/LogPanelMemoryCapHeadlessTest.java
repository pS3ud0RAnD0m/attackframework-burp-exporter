package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.allText;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.newPanel;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.resetPanelState;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.waitFor;
import static org.assertj.core.api.Assertions.assertThat;

class LogPanelMemoryCapHeadlessTest {

    @Test
    void oldestLinesAreTrimmed_whenModelCapExceeded() {
        LogPanel p = newPanel();
        resetPanelState(p);

        final int total = 5100;
        for (int i = 0; i < total; i++) {
            p.onLog("INFO", "line-" + i);
        }

        waitFor(() -> allText(p).contains("line-" + (total - 1)), 5000);

        String text = allText(p);
        assertThat(text).doesNotContain("line-0");
        assertThat(text).contains("line-5099");
    }
}
