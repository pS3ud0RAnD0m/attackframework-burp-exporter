package ai.attackframework.tools.burp.ui.primitives;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import ai.attackframework.tools.burp.ui.text.RegexIndicatorBinder;
import ai.attackframework.tools.burp.utils.Logger;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import net.miginfocom.swing.MigLayout;

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

    /**
     * Max number of rows permitted. The Add button disables at this limit.
     */
    private static final int MAX_ROWS = 100;

    private static final String TIP_ADD_ROW     = "Add new row";
    private static final String TIP_SCOPE_ENTRY = "Scope entry (string or regex)";
    private static final String TIP_REGEX_TOGGLE = "Interpret value as a regular expression.";
    private static final String TIP_DELETE_ROW  = "Delete this row";

    /**
     * Initial row seed for a custom entry.
     */
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

    /**
     * Tracks external enable/disable state to combine with the MAX_ROWS rule.
     */
    private boolean enabled = true;

    /**
     * Optional callback when any scope entry field or regex toggle changes.
     * Not serialized; set after construction by the owning panel.
     */
    private transient Runnable onContentChange;

    /**
     * Constructs the grid with optional seed entries.
     * <p>
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
        addButton.setToolTipText(TIP_ADD_ROW);
        addButton.addActionListener(e -> {
            if (rows.size() < MAX_ROWS) {
                rows.add(new Row("", true)); // new rows default to regex ON
                rebuild();
            }
            // No else: silently ignore beyond cap (button is disabled anyway when at cap)
        });

        rebuild();
    }

    /**
     * Returns the internal grid component to be added by higher-level panels.
     *
     * <p>This is an intentional exposure of a UI primitive so callers can
     * place the grid into their layouts; the panel is not shared across
     * independent owners.</p>
     * <p>
     * @return grid component to embed in layouts
     */
    @SuppressFBWarnings(value = "EI_EXPOSE_REP", justification = "ScopeGrid is a UI primitive; callers must embed the internal JPanel in their layouts.")
    public JPanel component() { return grid; }

    /**
     * Current text values across rows (in order).
     * <p>
     * @return list of row values
     */
    public List<String> values() {
        List<String> out = new ArrayList<>(rows.size());
        for (Row r : rows) out.add(r.field.getText());
        return out;
    }

    /**
     * Current kinds across rows (in order).
     * <p>
     * @return list of regex flags ({@code true} means regex)
     */
    public List<Boolean> regexKinds() {
        List<Boolean> out = new ArrayList<>(rows.size());
        for (Row r : rows) out.add(r.toggle.isSelected());
        return out;
    }

    /**
     * Replaces all rows with the provided entries.
     * A single blank row is created when {@code null} or empty.
     * <p>
     * @param entries new entries to apply
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
     * <p>
     * @param enabled whether controls should be enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        applyEnablement();
    }

    /**
     * Sets a callback invoked when any scope entry field or regex toggle changes.
     * Used so the config panel can push custom scope changes to {@link
     * ai.attackframework.tools.burp.utils.config.RuntimeConfig} without requiring a separate
     * button click.
     *
     * @param runnable callback to run on content change; {@code null} to clear
     */
    public void setOnContentChange(Runnable runnable) {
        this.onContentChange = runnable;
    }

    private void fireContentChange() {
        if (onContentChange != null) {
            onContentChange.run();
        }
    }

    /* ---------------- internal ---------------- */

    /**
     * Rebuilds the visual rows.
     * <p>
     * Caller must invoke on the EDT.
     */
    private void rebuild() {
        grid.removeAll();

        for (int i = 0; i < rows.size(); i++) {
            Row r = rows.get(i);
            r.assignNamesForIndex(i + 1);
            r.attachContentChangeListener(this::fireContentChange);

            assignRowToolTips(r);

            // Common part: field + toggle + indicator
            grid.add(r.field, "sg tf, growx"); // col 1
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

    /**
     * Ensures row-level tooltips are applied consistently.
     * <p>
     * @param r row to update
     */
    private static void assignRowToolTips(Row r) {
        r.field.setToolTipText(TIP_SCOPE_ENTRY);
        ensureToggleTextAndTip(r);
        r.delete.setToolTipText(TIP_DELETE_ROW);
    }

    /**
     * Applies enablement state to all row components.
     */
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

    /**
     * Standardizes toggle text and tooltip.
     * <p>
     * @param r row to adjust
     */
    private static void ensureToggleTextAndTip(Row r) {
        if (!".*".equals(r.toggle.getText())) r.toggle.setText(".*");
        r.toggle.setToolTipText(TIP_REGEX_TOGGLE);
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
        private boolean contentChangeListenerAttached;

        /**
         * Creates a row with provided value and regex flag.
         * <p>
         * @param value    initial field text
         * @param isRegex  whether regex toggle is selected
         */
        Row(String value, boolean isRegex) {
            field.setText(value);
            toggle.setSelected(isRegex);
            binding = RegexIndicatorBinder.bind(field, toggle, null, false, indicator);
        }

        /**
         * Attaches a listener so that any change to the field or toggle invokes the runnable.
         * Idempotent: only attaches once per row.
         */
        void attachContentChangeListener(Runnable onContentChange) {
            if (contentChangeListenerAttached || onContentChange == null) {
                return;
            }
            contentChangeListenerAttached = true;
            field.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) { onContentChange.run(); }
                @Override
                public void removeUpdate(DocumentEvent e) { onContentChange.run(); }
                @Override
                public void changedUpdate(DocumentEvent e) { onContentChange.run(); }
            });
            toggle.addItemListener(e -> onContentChange.run());
        }

        /**
         * Assigns deterministic component names for headless tests.
         * <p>
         * @param index1 1-based row index
         */
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

        /**
         * Binds the delete handler once, closing regex binding before removal.
         * <p>
         * @param onDelete callback invoked after cleanup
         */
        void ensureDeleteHandler(Runnable onDelete) {
            if (deleteBound) return;
            deleteBound = true;
            delete.addActionListener(e -> {
                try {
                    if (binding != null) binding.close();
                } catch (Exception ex) {
                    Logger.internalDebug("ScopeGrid.Row: error closing binding: " + ex);
                }
                onDelete.run();
            });
        }
    }
}
