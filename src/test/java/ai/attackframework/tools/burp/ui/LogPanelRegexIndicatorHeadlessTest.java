package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the regex validity indicators in LogPanel:
 * - When the regex toggle is off, the indicator is hidden and empty.
 * - When the regex toggle is on, the indicator shows ✖ for invalid input and ✓ for valid input.
 *
 * Private UI fields are accessed via the shared Reflection test utility to keep production visibility minimal.
 */
class LogPanelRegexIndicatorHeadlessTest {

    @Test
    void filter_regex_indicator_shows_check_or_cross() throws Exception {
        LogPanel panel = new LogPanel();

        JTextField filterField = get(panel, "filterField");
        JCheckBox filterRegexToggle = get(panel, "filterRegexToggle");
        JLabel indicator = get(panel, "filterRegexIndicator");

        // Off -> hidden
        SwingUtilities.invokeAndWait(() -> {
            filterRegexToggle.setSelected(false);
            filterField.setText("("); // invalid if regex were on
        });
        assertThat(indicator.isVisible()).isFalse();
        assertThat(indicator.getText()).isEmpty();

        // On + invalid -> ✖
        SwingUtilities.invokeAndWait(() -> {
            filterRegexToggle.setSelected(true);
            filterField.setText("("); // invalid regex
        });
        assertThat(indicator.isVisible()).isTrue();
        assertThat(indicator.getText()).isEqualTo("✖");

        // On + valid -> ✓
        SwingUtilities.invokeAndWait(() -> filterField.setText("foo.*bar"));
        assertThat(indicator.isVisible()).isTrue();
        assertThat(indicator.getText()).isEqualTo("✓");
    }

    @Test
    void search_regex_indicator_shows_check_or_cross() throws Exception {
        LogPanel panel = new LogPanel();

        JTextField searchField = get(panel, "searchField");
        JCheckBox searchRegexToggle = get(panel, "searchRegexToggle");
        JLabel indicator = get(panel, "searchRegexIndicator");

        // Off -> hidden
        SwingUtilities.invokeAndWait(() -> {
            searchRegexToggle.setSelected(false);
            searchField.setText("(");
        });
        assertThat(indicator.isVisible()).isFalse();
        assertThat(indicator.getText()).isEmpty();

        // On + invalid -> ✖
        SwingUtilities.invokeAndWait(() -> {
            searchRegexToggle.setSelected(true);
            searchField.setText("(");
        });
        assertThat(indicator.isVisible()).isTrue();
        assertThat(indicator.getText()).isEqualTo("✖");

        // On + valid -> ✓
        SwingUtilities.invokeAndWait(() -> searchField.setText("\\bfoo\\b"));
        assertThat(indicator.isVisible()).isTrue();
        assertThat(indicator.getText()).isEqualTo("✓");
    }
}
