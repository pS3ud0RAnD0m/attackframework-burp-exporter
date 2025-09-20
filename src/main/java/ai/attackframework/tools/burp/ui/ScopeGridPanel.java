package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.text.Doc;
import ai.attackframework.tools.burp.ui.text.RegexIndicatorBinder;
import net.miginfocom.swing.MigLayout;

import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.event.DocumentListener;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.io.Serial;
import java.util.ArrayList;
import java.util.List;

/**
 * Custom-scope grid for {@link ConfigPanel}.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Own row management (add/remove/renumber with first row protected).</li>
 *   <li>Own column layout and width harmonization for the text fields.</li>
 *   <li>Bind/unbind regex validity indicators (✓/✖) on a per-row basis.</li>
 * </ul>
 *
 * <p>Usage contract:
 * <ul>
 *   <li>All UI updates occur on the EDT.</li>
 *   <li>Listeners are installed at construction (for headless determinism) and re-installed in {@link #addNotify()},
 *       then closed in {@link #removeNotify()}.</li>
 *   <li>Stable component names are part of the testing contract:
 *       <code>scope.custom.regex</code> (first field),
 *       <code>scope.custom.regex.N</code> (N≥2),
 *       <code>scope.custom.regex.indicator.N</code> for indicators.</li>
 * </ul>
 *
 * <p>Pure UI component — no JSON/business logic.</p>
 */
public final class ScopeGridPanel extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    /** Component names used by tests. */
    private static final String NAME_SCOPE_CUSTOM = "scope.custom";
    private static final String NAME_SCOPE_CUSTOM_REGEX = "scope.custom.regex";
    private static final String NAME_SCOPE_CUSTOM_REGEX_INDICATOR = "scope.custom.regex.indicator";

    // Layout snippets
    private static final String MIG_INSETS0 = "insets 0";
    private static final String MIG_INSETS0_WRAP1 = "insets 0, wrap 1";
    private static final String MIG_GROWX = "growx";
    private static final String MIG_GROWX_WRAP = "growx, wrap";
    private static final String MIG_SPLIT_2 = "split 2";

    // First-row controls
    private final JRadioButton customRadio;
    private final JButton addButton;

    // Rows model (parallel lists; index 0 is the first, protected row)
    private final List<JTextField> fields = new ArrayList<>();
    private final List<JCheckBox> toggles = new ArrayList<>();
    private final List<JLabel> indicators = new ArrayList<>();

    // Container holding rows (each row is a JPanel with 4 columns)
    private final JPanel rowsContainer;

    // Regex binder handles for lifecycle management
    private final List<AutoCloseable> bindings = new ArrayList<>();

    // Row limits
    private static final int MAX_ROWS = 100;

    /** Initial row data for construction. */
    public record ScopeEntryInit(String value, boolean regex) { }

    /**
     * Constructs the grid with optional initial rows and an indent hint (stored only for completeness).
     * External indentation is applied by the parent layout.
     */
    public ScopeGridPanel(List<ScopeEntryInit> initial, int indentPx) {
        super(new MigLayout(MIG_INSETS0_WRAP1, "[grow]"));
        putClientProperty("indentPx", indentPx);

        this.rowsContainer = new JPanel(new MigLayout(MIG_INSETS0_WRAP1, "[grow]"));

        this.customRadio = new JRadioButton("Custom");
        this.customRadio.setName(NAME_SCOPE_CUSTOM);

        this.addButton = new JButton("Add");
        this.addButton.addActionListener(e -> addRow());

        // Build first row components and add to lists BEFORE sizing the indicator.
        JTextField firstField = new JTextField();
        firstField.setName(NAME_SCOPE_CUSTOM_REGEX);
        JCheckBox firstToggle = new JCheckBox(".*");
        JLabel firstIndicator = new JLabel();
        firstIndicator.setName(NAME_SCOPE_CUSTOM_REGEX_INDICATOR + ".1");

        fields.add(firstField);
        toggles.add(firstToggle);
        indicators.add(firstIndicator);

        sizeIndicatorLabel(firstIndicator, firstToggle, firstField);
        rowsContainer.add(buildRow(0, true), MIG_GROWX_WRAP);

        // Apply initial values (index 0) if provided; append additional rows if present
        if (initial != null && !initial.isEmpty()) {
            ScopeEntryInit init0 = initial.getFirst();
            if (init0 != null) {
                if (init0.value() != null) firstField.setText(init0.value());
                firstToggle.setSelected(init0.regex());
            }
            for (int i = 1; i < Math.min(initial.size(), MAX_ROWS); i++) {
                ScopeEntryInit it = initial.get(i);
                addRow();
                String v = (it == null || it.value() == null) ? "" : it.value();
                fields.get(i).setText(v);
                toggles.get(i).setSelected(it != null && it.regex());
            }
        }

        // Width harmonization: track all field changes
        DocumentListener dl = Doc.onChange(this::adjustFieldWidths);
        for (JTextField f : fields) f.getDocument().addDocumentListener(dl);

        add(rowsContainer, MIG_GROWX_WRAP);

        // Ensure indicators are bound even in headless tests that never call addNotify().
        rebindIndicators();

        adjustFieldWidths();
    }

    @Override
    public void addNotify() {
        super.addNotify();
        rebindIndicators();
    }

    @Override
    public void removeNotify() {
        closeBindings();
        super.removeNotify();
    }

    /** Returns the top-level component to embed in parent containers. */
    public JComponent component() { return this; }

    /** The "Custom" radio used for scope selection; intended to join an external ButtonGroup. */
    public JRadioButton customRadio() { return customRadio; }

    /** Current row values in visual order. */
    public List<String> values() {
        List<String> out = new ArrayList<>(fields.size());
        for (JTextField f : fields) out.add(f.getText());
        return out;
    }

    /** Regex kinds (true=regex, false=string) per row in visual order. */
    public List<Boolean> regexKinds() {
        List<Boolean> out = new ArrayList<>(toggles.size());
        for (JCheckBox c : toggles) out.add(c.isSelected());
        return out;
    }

    /** Sets the first row's value (keeps current toggle state). */
    public void setFirstValue(String value) {
        if (fields.isEmpty()) return;
        fields.getFirst().setText(value == null ? "" : value);
        adjustFieldWidths();
        revalidate();
        repaint();
    }

    /** Adds a new row at the end. First row is protected and always present. */
    public void addRow() {
        if (fields.size() >= MAX_ROWS) {
            addButton.setEnabled(false);
            return;
        }
        int nextIndex = fields.size(); // first extra row will be index 1

        JTextField field = new JTextField();
        field.setName(NAME_SCOPE_CUSTOM_REGEX + "." + (nextIndex + 1)); // first is unsuffixed; extras start at .2
        JCheckBox toggle = new JCheckBox(".*");
        JLabel indicator = new JLabel();
        indicator.setName(NAME_SCOPE_CUSTOM_REGEX_INDICATOR + "." + (nextIndex + 1));
        sizeIndicatorLabel(indicator, toggle, field);

        fields.add(field);
        toggles.add(toggle);
        indicators.add(indicator);

        rowsContainer.add(buildRow(nextIndex, false), MIG_GROWX_WRAP);

        field.getDocument().addDocumentListener(Doc.onChange(this::adjustFieldWidths));

        if (isDisplayable()) rebindIndicators();

        if (fields.size() >= MAX_ROWS) addButton.setEnabled(false);

        adjustFieldWidths();
        revalidate();
        repaint();
    }

    /**
     * Removes the row at the given visual index (0-based). Index 0 is protected.
     * Renumbers subsequent rows to preserve .N suffixes and indicator names.
     */
    public void removeRow(int index) {
        if (index <= 0 || index >= fields.size()) return;

        fields.remove(index);
        toggles.remove(index);
        indicators.remove(index);

        rowsContainer.removeAll();
        rowsContainer.add(buildRow(0, true), MIG_GROWX_WRAP);

        // Rebuild remaining rows with renumbered names
        for (int i = 1; i < fields.size(); i++) {
            JTextField f = fields.get(i);
            JCheckBox t = toggles.get(i);
            JLabel ind = indicators.get(i);

            f.setName(NAME_SCOPE_CUSTOM_REGEX + "." + (i + 1));
            ind.setName(NAME_SCOPE_CUSTOM_REGEX_INDICATOR + "." + (i + 1));
            sizeIndicatorLabel(ind, t, f);

            rowsContainer.add(buildRow(i, false), MIG_GROWX_WRAP);
        }

        if (fields.size() < MAX_ROWS) addButton.setEnabled(true);

        if (isDisplayable()) rebindIndicators();

        adjustFieldWidths();
        revalidate();
        repaint();
    }

    // ---- Internal helpers ----

    /** Build a row panel for the given index. */
    private JPanel buildRow(int index, boolean first) {
        JPanel row = new JPanel(new MigLayout(MIG_INSETS0, scopeCols()));
        if (first) {
            row.add(customRadio);
        } else {
            row.add(Box.createHorizontalStrut(radioColWidthPx()));
        }
        row.add(fields.get(index), MIG_GROWX);
        row.add(toggles.get(index), MIG_SPLIT_2);
        row.add(indicators.get(index));
        if (first) {
            row.add(addButton);
        } else {
            JButton delete = new JButton("Delete");
            delete.addActionListener(e -> removeRow(index));
            row.add(delete);
        }
        return row;
    }

    /** Column spec: radio/placeholder, text field, toggle+indicator, trailing button. */
    private String scopeCols() {
        return "[" + radioColWidthPx() + "!,left]10"
                + "[grow,fill]10"
                + "[" + toggleColWidthPx() + "!,left]10"
                + "[left]";
    }

    /** Width reserved for the radio column (col 1). */
    private int radioColWidthPx() {
        Dimension d = customRadio.getPreferredSize();
        int w = (d != null ? d.width : 0);
        return Math.max(80, w);
    }

    /** Max width of the validity indicator. */
    private int indicatorSlotWidthPx() {
        JLabel ok = new JLabel("✔");
        JLabel bad = new JLabel("✖");
        int w1 = ok.getPreferredSize() != null ? ok.getPreferredSize().width : 12;
        int w2 = bad.getPreferredSize() != null ? bad.getPreferredSize().width : 12;
        return Math.max(12, Math.max(w1, w2));
    }

    /** Baseline row height to avoid 0-height labels before layout. */
    private int indicatorHeightPx(JCheckBox toggleSample, JTextField fieldSample) {
        int hToggle = 0;
        int hSample = 0;
        int hField = 0;

        Dimension td = (toggleSample != null) ? toggleSample.getPreferredSize() : null;
        if (td != null) hToggle = td.height;

        Dimension sd = new JLabel("✔").getPreferredSize();
        if (sd != null) hSample = sd.height;

        Dimension fd = (fieldSample != null) ? fieldSample.getPreferredSize() : null;
        if (fd != null) hField = fd.height;

        int max = hToggle;
        if (hSample > max) max = hSample;
        if (hField > max) max = hField;
        return Math.max(12, max);
    }

    /** Fix the indicator label’s box so col 3 width/height remains stable. */
    private void sizeIndicatorLabel(JLabel label, JCheckBox toggleSample, JTextField fieldSample) {
        int w = indicatorSlotWidthPx();
        int h = indicatorHeightPx(toggleSample, fieldSample);
        Dimension d = new Dimension(w, h);
        label.setPreferredSize(d);
        label.setMinimumSize(d);
        label.setMaximumSize(d);
    }

    /** Total width to reserve for the toggle+indicator group (col 3). */
    private int toggleColWidthPx() {
        Dimension td = toggles.isEmpty() ? null : toggles.getFirst().getPreferredSize();
        int toggleW = (td != null ? td.width : 18);
        int gap = 6;
        return toggleW + indicatorSlotWidthPx() + gap;
    }

    /** Ensures all text fields share the same preferred width, clamped to sane bounds. */
    private void adjustFieldWidths() {
        if (fields.isEmpty()) return;

        int maxTextPx = 0;
        int height = fields.getFirst().getPreferredSize().height;
        for (JTextField f : fields) {
            FontMetrics fm = f.getFontMetrics(f.getFont());
            int w = fm.stringWidth(f.getText() == null ? "" : f.getText());
            if (w > maxTextPx) maxTextPx = w;
        }

        final int padding = 20;
        final int minW = 120;
        final int maxW = 900;
        int sum = maxTextPx + padding;
        int targetW = Math.clamp(sum, minW, maxW);

        for (JTextField f : fields) {
            Dimension d = new Dimension(targetW, height);
            f.setPreferredSize(d);
            f.setMinimumSize(new Dimension(minW, height));
        }

        rowsContainer.revalidate();
        rowsContainer.repaint();
    }

    /** Rebinds all indicators, closing any existing handles first. */
    private void rebindIndicators() {
        closeBindings();
        for (int i = 0; i < fields.size(); i++) {
            JTextField f = fields.get(i);
            JCheckBox t = toggles.get(i);
            JLabel ind = indicators.get(i);
            bindings.add(RegexIndicatorBinder.bind(f, t, null, false, ind));
        }
    }

    /** Closes and clears all stored regex indicator bindings. */
    private void closeBindings() {
        if (bindings.isEmpty()) return;
        for (AutoCloseable c : bindings) {
            try {
                if (c != null) c.close();
            } catch (Exception ignore) {
                // best-effort during disposal
            }
        }
        bindings.clear();
    }
}
