package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import javax.swing.text.StyledDocument;

import static org.assertj.core.api.Assertions.assertThat;

class LogPanelFilterRegexHeadlessTest {

    @Test
    void filter_regex_respects_case_toggle_and_matches_substrings() throws Exception {
        LogPanel panel = new LogPanel();

        JTextField filterField = get(panel, "filterField", JTextField.class);
        JCheckBox filterCaseToggle = get(panel, "filterCaseToggle", JCheckBox.class);
        JCheckBox filterRegexToggle = get(panel, "filterRegexToggle", JCheckBox.class);
        StyledDocument doc = get(panel, "doc", StyledDocument.class);

        // Ingest two messages with different casing
        panel.onLog("INFO", "Hello ABC");
        panel.onLog("INFO", "hello abc");

        // Ensure the REGEX filter is ON (use doClick so ActionListener fires and view rebuilds)
        SwingUtilities.invokeAndWait(() -> {
            if (!filterRegexToggle.isSelected()) filterRegexToggle.doClick();
        });

        // Case-insensitive: ensure the toggle is OFF (again via doClick for rebuild)
        SwingUtilities.invokeAndWait(() -> {
            if (filterCaseToggle.isSelected()) filterCaseToggle.doClick();
            filterField.setText("abc"); // DocumentListener triggers rebuild
        });
        String text1 = docText(doc);
        assertThat(text1).contains("Hello ABC");
        assertThat(text1).contains("hello abc");

        // Case-sensitive: turn toggle ON via doClick (rebuild happens in ActionListener)
        SwingUtilities.invokeAndWait(() -> {
            if (!filterCaseToggle.isSelected()) filterCaseToggle.doClick();
        });
        String text2 = docText(doc);
        assertThat(text2).doesNotContain("Hello ABC");
        assertThat(text2).contains("hello abc");
    }

    private static String docText(StyledDocument doc) throws BadLocationException {
        return doc.getText(0, doc.getLength());
    }

    private static <T> T get(Object target, String fieldName, Class<T> type) throws Exception {
        var f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return type.cast(f.get(target));
    }
}
