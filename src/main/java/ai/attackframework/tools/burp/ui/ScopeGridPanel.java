package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.text.RegexIndicatorBinder;
import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import java.awt.Dimension;
import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Custom-scope rows rendered in a single 4-column grid:
 * <ol>
 *   <li>Radio (row 1) / placeholder (rows &gt; 1)</li>
 *   <li>Text field (size-grouped so all fields share the same width)</li>
 *   <li>{@code ".*"} toggle + indicator (same cell)</li>
 *   <li>Action button (Add on row 1, Delete on rows &gt; 1; size-grouped)</li>
 * </ol>
 *
 * <p><strong>EDT:</strong> Public mutators expect to be called on the EDT.</p>
 */
public class ScopeGridPanel implements Serializable {

    @Serial private static final long serialVersionUID = 1L;

    /** Initial row seed for a custom entry. */
    public record ScopeEntryInit(String value, boolean regex) implements Serializable {
        @Serial private static final long serialVersionUID = 1L;
    }

    private static final int MAX_ROWS = 100;
    private static final String SG_FIELD = "sg field";
    private static final String SG_BTN   = "sg btn";
    private static final String GROWX    = "growx";

    /**
     * Single grid containing all rows (no forced wrap-per-component).
     * Columns: radio/placeholder | field | regex+indicator | button.
     */
    private final JPanel grid = new JPanel(
            new MigLayout(
                    "insets 0, gapx 10, gapy 6",
                    "[]10[fill,grow," + SG_FIELD + "]10[]10[" + SG_BTN + ",left]"
            )
    );

    private final JRadioButton customRadio = new JRadioButton("Custom");
    private final List<Row> rows = new ArrayList<>();
    private final JButton addButton = new JButton("Add");

    /**
     * Constructs the grid with optional seed entries.
     * @param initial ordered initial entries; blank row created when {@code null} or empty
     */
    public ScopeGridPanel(List<ScopeEntryInit> initial) {
        customRadio.setName("scope.custom");
        customRadio.addItemListener(e -> updateEnabledState(customRadio.isSelected()));

        if (initial == null || initial.isEmpty()) {
            rows.add(new Row("", true)); // default regex ON
        } else {
            for (ScopeEntryInit se : initial) {
                rows.add(new Row(Objects.requireNonNullElse(se.value(), ""), se.regex()));
            }
        }

        addButton.setName("scope.custom.add");
        addButton.addActionListener(e -> {
            if (rows.size() < MAX_ROWS) {
                rows.add(new Row("", true)); // new rows default regex ON
                rebuild();
            }
        });

        rebuild();
        updateEnabledState(customRadio.isSelected()); // default: disabled until Custom selected
    }

    /** The radio used to select custom scope. */
    public JRadioButton customRadio() { return customRadio; }

    /** Returns the grid component to be added by ConfigPanel. */
    public JPanel component() { return grid; }

    /** Current text values across rows (in order). */
    public List<String> values() {
        List<String> out = new ArrayList<>(rows.size());
        for (Row r : rows) out.add(r.field.getText());
        return out;
    }

    /** Current kinds across rows (in order). {@code true} means the row is regex. */
    public List<Boolean> regexKinds() {
        List<Boolean> out = new ArrayList<>(rows.size());
        for (Row r : rows) out.add(r.toggle.isSelected());
        return out;
    }

    /**
     * Replaces all rows with the provided entries.
     * @param entries ordered entries; a single blank row is created when {@code null} or empty
     */
    public void setEntries(List<ScopeEntryInit> entries) {
        rows.clear();
        if (entries == null || entries.isEmpty()) {
            rows.add(new Row("", true));
        } else {
            for (ScopeEntryInit se : entries) {
                rows.add(new Row(Objects.requireNonNullElse(se.value(), ""), se.regex()));
            }
        }
        rebuild();
        updateEnabledState(customRadio.isSelected());
    }

    /* ---------------- internal ---------------- */

    /** Enables/disables all row controls and the Add button based on custom selection. */
    private void updateEnabledState(boolean customSelected) {
        for (int i = 0; i < rows.size(); i++) {
            Row r = rows.get(i);
            boolean enableRow = customSelected;
            r.field.setEnabled(enableRow);
            r.toggle.setEnabled(enableRow);
            r.delete.setEnabled(enableRow && i > 0); // row 1 has no Delete
        }
        addButton.setEnabled(customSelected && rows.size() < MAX_ROWS);
        grid.revalidate();
        grid.repaint();
    }

    /** Rebuilds the visual rows; caller must invoke on the EDT. */
    private void rebuild() {
        grid.removeAll();

        // Width used for placeholders so textboxes in col 2 align under the first row’s field
        Dimension radioSize = customRadio.getPreferredSize();

        for (int i = 0; i < rows.size(); i++) {
            int idx = i + 1;
            Row r = rows.get(i);
            r.assignNamesForIndex(idx);

            if (idx == 1) {
                // Row 1: Custom radio | field | toggle+indicator | Add
                grid.add(customRadio);                       // col 1
                grid.add(r.field, GROWX);                    // col 2 (sg field)
                ensureToggleText(r);
                grid.add(r.toggle, "split 2");               // col 3 (toggle + indicator)
                grid.add(r.indicator);
                grid.add(addButton);                         // col 4 (sg btn)
            } else {
                // Rows > 1: placeholder | field | toggle+indicator | Delete
                JLabel placeholder = new JLabel();
                placeholder.setPreferredSize(new Dimension(radioSize.width, radioSize.height));
                grid.add(placeholder);                       // col 1
                grid.add(r.field, GROWX);                    // col 2 (sg field)
                ensureToggleText(r);
                grid.add(r.toggle, "split 2");               // col 3
                grid.add(r.indicator);
                r.ensureDeleteHandler(() -> {
                    rows.remove(r);
                    rebuild();
                    updateEnabledState(customRadio.isSelected());
                });
                grid.add(r.delete);                           // col 4 (sg btn)
            }

            // Wrap to start a new row
            grid.add(new JLabel(), "wrap");
        }

        addButton.setEnabled(customRadio.isSelected() && rows.size() < MAX_ROWS);

        grid.revalidate();
        grid.repaint();
    }

    private static void ensureToggleText(Row r) {
        if (!".*".equals(r.toggle.getText())) r.toggle.setText(".*");
    }

    /** Row model: text field, toggle, indicator, and (rows &gt; 1) a delete button. */
    private static final class Row implements Serializable {
        @Serial private static final long serialVersionUID = 1L;

        private final JTextField field = new JTextField();
        private final JCheckBox  toggle = new JCheckBox(".*");
        private final JLabel     indicator = new JLabel(); // ✓ / ✖ glyph
        private final JButton    delete = new JButton("Delete");
        private final transient AutoCloseable binding;
        private boolean deleteBound;

        Row(String value, boolean isRegex) {
            field.setText(value);
            toggle.setSelected(isRegex);
            binding = RegexIndicatorBinder.bind(field, toggle, null, false, indicator);
        }

        void assignNamesForIndex(int index1) {
            if (index1 == 1) {
                field.setName("scope.custom.regex");
                toggle.setName("scope.custom.toggle");
            } else {
                field.setName("scope.custom.regex." + index1);
                toggle.setName("scope.custom.toggle." + index1);
            }
            indicator.setName("scope.custom.regex.indicator." + index1);
            delete.setName("scope.custom.delete." + index1);
        }

        void ensureDeleteHandler(Runnable onDelete) {
            if (deleteBound) return;
            deleteBound = true;
            delete.addActionListener(e -> {
                try { if (binding != null) binding.close(); } catch (Exception ignored) { /* no-op */ }
                onDelete.run();
            });
        }
    }
}
