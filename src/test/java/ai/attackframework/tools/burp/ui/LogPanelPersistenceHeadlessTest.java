package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JTextField;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ensures min-level, pause flag, filter text, and last search query persist across new instances.
 */
class LogPanelPersistenceHeadlessTest {

    @Test
    void persists_minLevel_pause_filterText_lastSearch() {
        // Instance A: set values
        LogPanel a = newPanel();

        @SuppressWarnings("unchecked")
        JComboBox<String> level = (JComboBox<String>) combo(a, "log.filter.level");
        level.setSelectedItem("WARN");

        JCheckBox pause = check(a, "Pause autoscroll");
        if (!pause.isSelected()) click(pause);

        JTextField filter = field(a, "log.filter.text");
        setText(filter, "persist-me");

        JTextField search = field(a, "log.search.field");
        setText(search, "needle");

        // Simulate panel lifecycle end
        a.removeNotify();

        // Instance B: verify restoration
        LogPanel b = newPanel();

        @SuppressWarnings("unchecked")
        JComboBox<String> levelB = (JComboBox<String>) combo(b, "log.filter.level");
        assertThat(levelB.getSelectedItem()).isEqualTo("WARN");

        JCheckBox pauseB = check(b, "Pause autoscroll");
        assertThat(pauseB.isSelected()).isTrue();

        JTextField filterB = field(b, "log.filter.text");
        assertThat(filterB.getText()).isEqualTo("persist-me");

        JTextField searchB = field(b, "log.search.field");
        assertThat(searchB.getText()).isEqualTo("needle");
    }
}
