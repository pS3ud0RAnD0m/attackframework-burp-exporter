package ai.anomalousvectors.tools.burp.ui;

import javax.swing.JCheckBox;

import org.junit.jupiter.api.Test;

import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.allText;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.check;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.click;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.field;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.newPanel;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.resetPanelState;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.setText;
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

    @Test
    void textFilter_negative_excludesMatchingLines() {
        LogPanel p = newPanel();
        resetPanelState(p);

        setText(field(p, "log.filter.text"), "ParameterCardinality");
        JCheckBox negative = check(p, "log.filter.negative");
        if (!negative.isSelected()) {
            click(negative);
        }

        p.onLog("INFO", "[ParameterCardinality] skipped body");
        p.onLog("INFO", "[StartupExport] ProxyHistory: exporting backlog: 10 item(s).");

        String text = allText(p);
        assertThat(text)
                .doesNotContain("ParameterCardinality")
                .contains("ProxyHistory");
    }
}
