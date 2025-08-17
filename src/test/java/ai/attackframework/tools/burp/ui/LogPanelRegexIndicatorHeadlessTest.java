package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;

class LogPanelRegexIndicatorHeadlessTest {

    @Test
    void filter_regex_indicator_shows_check_or_cross() throws Exception {
        LogPanel panel = new LogPanel();

        JTextField filterField = get(panel, "filterField", JTextField.class);
        JCheckBox filterRegexToggle = get(panel, "filterRegexToggle", JCheckBox.class);
        JLabel indicator = get(panel, "filterRegexIndicator", JLabel.class);

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

        JTextField searchField = get(panel, "searchField", JTextField.class);
        JCheckBox searchRegexToggle = get(panel, "searchRegexToggle", JCheckBox.class);
        JLabel indicator = get(panel, "searchRegexIndicator", JLabel.class);

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

    // ---- reflection helper ----
    private static <T> T get(Object target, String fieldName, Class<T> type) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        Object v = f.get(target);
        return type.cast(v);
    }
}
