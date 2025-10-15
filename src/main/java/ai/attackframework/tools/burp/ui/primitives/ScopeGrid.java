package ai.attackframework.tools.burp.ui.primitives;

import ai.attackframework.tools.burp.ui.text.RegexIndicatorBinder;
import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Custom scope entries grid:
 * - Col 1: text field (size-grouped)
 * - Col 2: ".*" toggle + ✓/✖ indicator
 * - Col 3: action button (Add on row 1, Delete on rows > 1)
 *
 * <p><strong>EDT:</strong> Public mutators expect to be called on the EDT.</p>
 */
public class ScopeGrid implements Serializable {

    @Serial private static final long serialVersionUID = 1L;

    /** Max number of rows permitted. The Add button disables at this limit. */
    private static final int MAX_ROWS = 100;

    /** Initial row seed for a custom entry. */
    public record ScopeEntryInit(String value, boolean regex) implements Serializable {
        @Serial private static final long serialVersionUID = 1L;
    }

    // Single grid containing all rows (no forced wrap-per-component).
    // Parent composite (ConfigScopePanel) provides the [150!,left]20[...] columns; this
    // grid starts at the "fields" column and keeps Sink alignment stable.
    private final JPanel grid = new JPanel(
            new MigLayout(
                    "insets 0, gapx 20, gapy 6",
                    "[fill,grow,sg tf]20[]20[sg btn,left]"
            )
    );

    private final List<Row> rows = new ArrayList<>();
    private final JButton addButton = new JButton("Add");

    /** Tracks external enable/disable state to combine with the MAX_ROWS rule. */
    private boolean enabled = true;

    /**
     * Constructs the grid with optional seed entries.
     * @param initial ordered initial entries; blank row created when {@code null} or empty
     */
    public ScopeGrid(List<ScopeEntryInit> initial) {
        if (initial == null || initial.isEmpty()) {
            rows.add(new Row("", true)); // default: regex ON
        } else {
            for (ScopeEntryInit se : initial) {
                rows.add(new Row(Objects.requireNonNullElse(se.value(), ""), se.regex()));
            }
        }

        addButton.setName("scope.custom.add");
        addButton.setToolTipText("Add new row");
        addButton.addActionListener(e -> {
            if (rows.size() < MAX_ROWS) {
                rows.add(new Row("", true)); // new rows default to regex ON
                rebuild();
            }
            // No else: silently ignore beyond cap (button is disabled anyway when at cap)
        });

        rebuild();
    }

    /** Returns the grid component to be added by higher-level panels. */
    public JPanel component() { return grid; }

    /** Current text values across rows (in order). */
    public List<String> values() {
        List<String> out = new ArrayList<>(rows.size());
        for (Row r : rows) out.add(r.field.getText());
        return out;
    }

    /** Current kinds across rows (in order). {@code true} means regex. */
    public List<Boolean> regexKinds() {
        List<Boolean> out = new ArrayList<>(rows.size());
        for (Row r : rows) out.add(r.toggle.isSelected());
        return out;
    }

    /**
     * Replaces all rows with the provided entries.
     * A single blank row is created when {@code null} or empty.
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
    }

    /**
     * Enables/disables the entire grid (fields, toggles, Add/Delete).
     * The Add button is also constrained by the MAX_ROWS rule.
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        applyEnablement();
    }

    /* ---------------- internal ---------------- */

    /** Rebuilds the visual rows; caller must invoke on the EDT. */
    private void rebuild() {
        grid.removeAll();

        for (int i = 0; i < rows.size(); i++) {
            Row r = rows.get(i);
            r.assignNamesForIndex(i + 1);

            // Common part: field + toggle + indicator
            grid.add(r.field, "sg tf, growx"); // col 1
            ensureToggleTextAndTip(r);
            grid.add(r.toggle, "split 2");     // col 2
            grid.add(r.indicator);

            if (i == 0) {
                // Row 1 has Add
                grid.add(addButton, "sg btn"); // col 3
            } else {
                // Rows > 1 have Delete
                r.ensureDeleteHandler(() -> {
                    rows.remove(r);
                    rebuild();
                });
                grid.add(r.delete, "sg btn");  // col 3
            }

            grid.add(new JLabel(), "wrap");
        }

        applyEnablement();
        grid.revalidate();
        grid.repaint();
    }

    private void applyEnablement() {
        boolean canAdd = enabled && rows.size() < MAX_ROWS;
        addButton.setEnabled(canAdd);
        for (int i = 0; i < rows.size(); i++) {
            Row r = rows.get(i);
            r.field.setEnabled(enabled);
            r.toggle.setEnabled(enabled);
            r.delete.setEnabled(enabled && i > 0);
        }
    }

    private static void ensureToggleTextAndTip(Row r) {
        if (!".*".equals(r.toggle.getText())) r.toggle.setText(".*");
        r.toggle.setToolTipText("Interpret value as a regular expression.");
    }

    /** Row model: text field, toggle, indicator, and (rows &gt; 1) a Delete button. */
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
            delete.setToolTipText("Delete this row");
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
