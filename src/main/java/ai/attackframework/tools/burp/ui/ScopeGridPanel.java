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
 * Renders the Custom scope rows so that:
 * - Row 1: Custom radio + first textbox + ".*" toggle + indicator + Add
 * - Rows N>1: placeholder (radio-width) + textbox + ".*" toggle + indicator + Delete
 *
 * Stable names (tested):
 *  - First field: scope.custom.regex
 *  - Subsequent:  scope.custom.regex.N
 *  - Toggles:     scope.custom.toggle (first) / scope.custom.toggle.N
 *  - Indicators:  scope.custom.regex.indicator.N
 *  - Deletes:     scope.custom.delete.N (N>1 only)
 *  - Add button:  scope.custom.add
 *  - Radio:       scope.custom
 */
public class ScopeGridPanel implements Serializable {

    @Serial private static final long serialVersionUID = 1L;

    public record ScopeEntryInit(String value, boolean regex) implements Serializable {
        @Serial private static final long serialVersionUID = 1L;
    }

    private static final int MAX_ROWS = 100;
    private static final String GROWX = "growx";

    /** Outer container with one row panel per visual row (keeps tests happy). */
    private final JPanel grid = new JPanel(new MigLayout("insets 0, gapy 0, wrap 1", "[fill]"));

    private final JRadioButton customRadio = new JRadioButton("Custom");
    private final List<Row> rows = new ArrayList<>();
    private final JButton addButton = new JButton("Add");

    public ScopeGridPanel(List<ScopeEntryInit> initial) {
        customRadio.setName("scope.custom");

        if (initial == null || initial.isEmpty()) {
            rows.add(new Row("", false));
        } else {
            for (ScopeEntryInit se : initial) {
                rows.add(new Row(Objects.requireNonNullElse(se.value(), ""), se.regex()));
            }
        }

        addButton.setName("scope.custom.add");
        addButton.addActionListener(e -> {
            if (rows.size() < MAX_ROWS) {
                rows.add(new Row("", false));
                rebuild();
            }
        });

        rebuild();
    }

    /** The radio used to select custom scope. */
    public JRadioButton customRadio() { return customRadio; }

    /** Returns the grid component (ConfigPanel applies outer indentation). */
    public JPanel component() { return grid; }

    /** Current text values across rows. */
    public List<String> values() {
        List<String> out = new ArrayList<>(rows.size());
        for (Row r : rows) out.add(r.field.getText());
        return out;
    }

    /** Current kinds across rows (true = regex). */
    public List<Boolean> regexKinds() {
        List<Boolean> out = new ArrayList<>(rows.size());
        for (Row r : rows) out.add(r.toggle.isSelected());
        return out;
    }

    /** Replace all rows (empty list yields a single blank row). */
    public void setEntries(List<ScopeEntryInit> entries) {
        rows.clear();
        if (entries == null || entries.isEmpty()) {
            rows.add(new Row("", false));
        } else {
            for (ScopeEntryInit se : entries) {
                rows.add(new Row(Objects.requireNonNullElse(se.value(), ""), se.regex()));
            }
        }
        rebuild();
    }

    /* ---------------- internal ---------------- */

    private void rebuild() {
        grid.removeAll();

        // Reference size: width of the radio so placeholders match it
        Dimension radioSize = customRadio.getPreferredSize();

        for (int i = 0; i < rows.size(); i++) {
            int idx = i + 1;
            Row r = rows.get(i);
            r.assignNamesForIndex(idx);

            // Per-row panel ensures field.getParent() is the row, not the whole grid (test requirement)
            JPanel rp = new JPanel(new MigLayout("insets 0, gapx 10", "[]10[fill,grow]10[]10[]10[]"));

            if (idx == 1) {
                // First row: radio + field + toggle + indicator + Add
                rp.add(customRadio);
                rp.add(r.field, GROWX);
                ensureToggleText(r);
                rp.add(r.toggle);
                rp.add(r.indicator);
                rp.add(addButton);
            } else {
                // Subsequent rows: placeholder with radio's width, then controls
                JLabel placeholder = new JLabel();
                placeholder.setPreferredSize(new Dimension(radioSize.width, radioSize.height));
                rp.add(placeholder);
                rp.add(r.field, GROWX);
                ensureToggleText(r);
                rp.add(r.toggle);
                rp.add(r.indicator);

                r.ensureDeleteHandler(() -> {
                    rows.remove(r);
                    rebuild();
                });
                rp.add(r.delete);
            }

            grid.add(rp, GROWX + ", wrap");
        }

        addButton.setEnabled(rows.size() < MAX_ROWS);

        grid.revalidate();
        grid.repaint();
    }

    private static void ensureToggleText(Row r) {
        if (!".*".equals(r.toggle.getText())) r.toggle.setText(".*");
    }

    /** Represents a single row (one set of controls). */
    private static final class Row implements Serializable {
        @Serial private static final long serialVersionUID = 1L;

        private final JTextField field = new JTextField();
        private final JCheckBox toggle = new JCheckBox(".*");
        private final JLabel indicator = new JLabel(); // ✓ / ✖ glyph
        private final JButton delete = new JButton("Delete");
        private final transient AutoCloseable binding; // UI listener handle
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
