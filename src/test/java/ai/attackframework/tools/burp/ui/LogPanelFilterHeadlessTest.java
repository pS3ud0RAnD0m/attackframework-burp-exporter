package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JComboBox;
import javax.swing.JCheckBox;
import javax.swing.JTextField;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.*;
import static org.assertj.core.api.Assertions.assertThat;

class LogPanelFilterHeadlessTest {

    @Test
    void textFilter_plain_caseInsensitive() {
        LogPanel p = newPanel();

        // Level = DEBUG (verbose so we see all)
        @SuppressWarnings("unchecked")
        JComboBox<String> lvl = (JComboBox<String>) combo(p, "log.filter.level");
        LogPanelTestHarness.waitFor(() -> lvl.getItemCount() > 0, 1000);
        lvl.setSelectedItem("DEBUG");

        JTextField filter = field(p, "log.filter.text");
        setText(filter, "traffic"); // case-insensitive by default

        p.onLog("INFO", "Sitemap indexed");
        p.onLog("INFO", "Traffic captured");
        p.onLog("INFO", "TRAFFIC exported");

        String text = allText(p);
        assertThat(text).contains("Traffic captured");
        assertThat(text).contains("TRAFFIC exported");
        assertThat(text).doesNotContain("Sitemap indexed");
    }

    @Test
    void textFilter_regex_caseSensitive() {
        LogPanel p = newPanel();

        // turn on case + regex for filter group
        JCheckBox caseToggle = check(p, "Aa");
        JCheckBox regexToggle = check(p, ".*");
        if (!caseToggle.isSelected()) click(caseToggle);
        if (!regexToggle.isSelected()) click(regexToggle);

        JTextField filter = field(p, "log.filter.text");
        setText(filter, "^Findings\\b");

        p.onLog("INFO", "Findings loaded");
        p.onLog("INFO", "findings lower");
        p.onLog("INFO", "Traffic");

        String text = allText(p);
        assertThat(text).contains("Findings loaded");
        assertThat(text).doesNotContain("findings lower");
        assertThat(text).doesNotContain("Traffic");
    }
}
