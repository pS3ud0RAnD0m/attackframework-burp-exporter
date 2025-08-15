package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the panel trims old entries as it grows (model cap).
 */
class LogPanelMemoryCapHeadlessTest {

    @Test
    void oldestLinesAreTrimmed_whenModelCapExceeded() {
        LogPanel p = newPanel();

        // push a bit past the cap with unique lines (no compaction)
        final int total = 5100;
        for (int i = 0; i < total; i++) {
            p.onLog("INFO", "line-" + i);
        }

        // wait until the last line appears
        waitFor(() -> allText(p).contains("line-" + (total - 1)), 5000);

        String text = allText(p);
        // earliest lines should be trimmed out
        assertThat(text).doesNotContain("line-0");
        assertThat(text).contains("line-5099");
    }
}
