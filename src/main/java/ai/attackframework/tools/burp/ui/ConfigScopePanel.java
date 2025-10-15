package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.primitives.ScopeGrid;
import net.miginfocom.swing.MigLayout;

import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import java.awt.Component;
import java.awt.Font;
import java.util.Objects;

/**
 * Builds the "Scope" section panel used by ConfigPanel.
 * Components are owned by ConfigPanel and injected to keep a single source of state.
 */
public record ConfigScopePanel(
        JRadioButton allRadio,
        JRadioButton burpRadio,
        JRadioButton customRadio,
        ScopeGrid grid,
        int indentPx
) {

    private static final String GAPLEFT = "gapleft ";
    private static final String ALIGN_LEFT_TOP = "alignx left, top";

    public ConfigScopePanel {
        Objects.requireNonNull(allRadio, "allRadio");
        Objects.requireNonNull(burpRadio, "burpRadio");
        Objects.requireNonNull(customRadio, "customRadio");
        Objects.requireNonNull(grid, "grid");
    }

    /**
     * Returns a panel containing Scope header, radios, and the custom grid row.
     * Layout mirrors other sections (Sources/Sinks/Admin) and aligns the grid's field
     * column with Sinks (first column 150!, gap 20).
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
