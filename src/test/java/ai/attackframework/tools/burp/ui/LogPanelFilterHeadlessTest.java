package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.allText;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.field;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.newPanel;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.resetPanelState;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.setText;
import static org.assertj.core.api.Assertions.assertThat;

class LogPanelFilterHeadlessTest {

    @Test
    void textFilter_plain_caseInsensitive() {
        LogPanel p = newPanel();
        resetPanelState(p);

        setText(field(p, "log.filter.text"), "traffic");

        p.onLog("INFO", "Traffic captured");
        p.onLog("INFO", "Findings loaded");
        p.onLog("INFO", "other text");

        String text = allText(p);
        assertThat(text)
                .contains("Traffic captured")
                .doesNotContain("Findings loaded");
    }
}
