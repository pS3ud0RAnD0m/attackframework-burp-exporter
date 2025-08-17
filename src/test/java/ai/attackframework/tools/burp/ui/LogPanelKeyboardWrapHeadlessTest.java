package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.AbstractAction;
import javax.swing.ActionMap;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;

class LogPanelKeyboardWrapHeadlessTest {

    @Test
    void enter_advances_and_wraps_matches_updating_count_label() throws Exception {
        LogPanel panel = new LogPanel();

        // Controls used in this test
        JTextField searchField      = get(panel, "searchField", JTextField.class);
        JCheckBox  searchCaseToggle = get(panel, "searchCaseToggle", JCheckBox.class);
        JCheckBox  searchRegexToggle= get(panel, "searchRegexToggle", JCheckBox.class);
        JLabel     count            = get(panel, "searchCountLabel", JLabel.class);

        // IMPORTANT: clear any persisted *filter* so the doc actually contains the ingested lines
        JTextField filterField        = get(panel, "filterField", JTextField.class);
        JCheckBox  filterCaseToggle   = get(panel, "filterCaseToggle", JCheckBox.class);
        JCheckBox  filterRegexToggle  = get(panel, "filterRegexToggle", JCheckBox.class);
        SwingUtilities.invokeAndWait(() -> {
            if (filterRegexToggle.isSelected()) filterRegexToggle.doClick();
            if (filterCaseToggle.isSelected())  filterCaseToggle.doClick();
            filterField.setText(""); // DocumentListener will rebuild view
        });
        flushEdt();

        // Ingest two lines, then flush EDT to ensure they're rendered
        panel.onLog("INFO", "alpha BETA");
        panel.onLog("INFO", "Alpha beta");
        flushEdt();

        // Plain, case-insensitive search for "alpha"
        SwingUtilities.invokeAndWait(() -> {
            if (searchRegexToggle.isSelected()) searchRegexToggle.doClick();
            if (searchCaseToggle.isSelected())  searchCaseToggle.doClick();
            searchField.setText("alpha"); // triggers compute via DocumentListener
        });
        flushEdt();

        assertThat(count.getText()).isEqualTo("1/2");

        // Use the same action the ENTER key is bound to
        ActionMap am = searchField.getActionMap();
        AbstractAction next = (AbstractAction) am.get("log.search.next");

        SwingUtilities.invokeAndWait(() -> next.actionPerformed(null));
        flushEdt();
        assertThat(count.getText()).isEqualTo("2/2");

        // Wrap around to first match
        SwingUtilities.invokeAndWait(() -> next.actionPerformed(null));
        flushEdt();
        assertThat(count.getText()).isEqualTo("1/2");
    }

    private static void flushEdt() throws Exception {
        SwingUtilities.invokeAndWait(() -> { /* drain EDT */ });
    }

    @SuppressWarnings("unchecked")
    private static <T> T get(Object target, String fieldName, Class<T> type) throws Exception {
        var f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return (T) type.cast(f.get(target));
    }
}
