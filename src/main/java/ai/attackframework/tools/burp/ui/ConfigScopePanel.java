package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Font;
import java.util.Objects;

import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

import ai.attackframework.tools.burp.ui.primitives.ScopeGrid;
import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Scope" section panel used by ConfigPanel.
 * Components are owned by ConfigPanel and injected to keep a single source of state.
 */
public final class ConfigScopePanel {

    private final JRadioButton allRadio;
    private final JRadioButton burpRadio;
    private final JRadioButton customRadio;
    private final ScopeGrid grid;
    private final int indentPx;

    private static final String GAPLEFT = "gapleft ";
    private static final String ALIGN_LEFT_TOP = "alignx left, top";

    public ConfigScopePanel(
            JRadioButton allRadio,
            JRadioButton burpRadio,
            JRadioButton customRadio,
            ScopeGrid grid,
            int indentPx
    ) {
        this.allRadio = Objects.requireNonNull(allRadio, "allRadio");
        this.burpRadio = Objects.requireNonNull(burpRadio, "burpRadio");
        this.customRadio = Objects.requireNonNull(customRadio, "customRadio");
        this.grid = Objects.requireNonNull(grid, "grid");
        this.indentPx = indentPx;
    }

    /**
     * Builds the Scope section UI containing header, radios, and the custom grid row.
     *
     * <p>Caller must invoke on the EDT. Layout mirrors other sections (Sources/Sinks/Control) and
     * aligns the grid's field column with Sinks (first column 150!, gap 20).</p>
     *
     * @return assembled panel with scope controls and custom grid
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[left]", ""));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel title = new JLabel("Scope");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(title, "gapbottom 6");

        // Group radios
        ButtonGroup group = new ButtonGroup();
        group.add(allRadio);
        group.add(burpRadio);
        group.add(customRadio);

        // Burp radio (indented)
        panel.add(burpRadio, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);

        // Custom row: two columns — [150!, left]20[grid (fields)]
        JPanel customRow = new JPanel(new MigLayout("insets 0", "[150!,left]20[fill,grow]", ""));
        customRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        customRow.add(customRadio, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);
        customRow.add(grid.component(), "growx");
        panel.add(customRow, "growx, gapbottom 4");

        // All radio (indented)
        panel.add(allRadio, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);

        // UI-only enablement: grid active only when Custom is selected
        Runnable refresh = () -> grid.setEnabled(customRadio.isSelected());
        customRadio.addItemListener(e -> refresh.run());
        burpRadio.addItemListener(e -> refresh.run());
        allRadio.addItemListener(e -> refresh.run());
        refresh.run(); // initial

        return panel;
    }
}
