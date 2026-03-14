package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Font;
import java.util.Map;
import java.util.Objects;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import ai.attackframework.tools.burp.ui.primitives.ButtonStyles;
import ai.attackframework.tools.burp.utils.config.ExportFieldRegistry;
import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Index Fields" section panel: per-index expand/collapse groups with checkboxes
 * for toggleable export fields. Layout uses wrapping so all fields are in view when expanded.
 */
public final class ConfigFieldsPanel {

    private static final String EXPAND_COLLAPSED = "+";
    private static final String EXPAND_EXPANDED = "−";
    private static final String GAPLEFT = "gapleft ";

    private final Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex;
    private final Map<String, JButton> expandButtonsByIndex;
    private final Map<String, JPanel> subPanelsByIndex;
    private final int indentPx;

    public ConfigFieldsPanel(
            Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex,
            Map<String, JButton> expandButtonsByIndex,
            Map<String, JPanel> subPanelsByIndex,
            int indentPx) {
        this.fieldCheckboxesByIndex = Objects.requireNonNull(fieldCheckboxesByIndex);
        this.expandButtonsByIndex = Objects.requireNonNull(expandButtonsByIndex);
        this.subPanelsByIndex = Objects.requireNonNull(subPanelsByIndex);
        this.indentPx = indentPx;
    }

    /**
     * Builds the Index Fields section: title and one expandable group per index with checkboxes.
     * Sub-panels start collapsed. Caller must invoke on the EDT.
     * If {@code sectionHeaderRowsOut} is non-null, it is filled with index name -> header row panel for enable/disable.
     */
    public JPanel build(java.util.Map<String, JPanel> sectionHeaderRowsOut) {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1, hidemode 3", "[grow,left]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = new JLabel("Index Fields");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        header.setToolTipText("Configure the index fields to export for each document.");
        panel.add(header, "gapbottom 6, wrap");

        int subIndent = indentPx * 2;

        for (String indexName : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            JButton expandBtn = expandButtonsByIndex.get(indexName);
            JPanel subPanel = subPanelsByIndex.get(indexName);
            if (expandBtn == null || subPanel == null) continue;

            String displayName = indexDisplayName(indexName);
            JLabel indexLabel = new JLabel(displayName);
            indexLabel.setToolTipText(indexTooltip(indexName));

            JPanel parentRow = new JPanel(new MigLayout("insets 0, aligny center", "[left]6[pref!]"));
            parentRow.setOpaque(false);
            parentRow.add(indexLabel, GAPLEFT + indentPx + ", aligny center");
            parentRow.add(expandBtn, "aligny center");

            if (sectionHeaderRowsOut != null) {
                sectionHeaderRowsOut.put(indexName, parentRow);
            }

            panel.add(parentRow, "growx, wrap");
            panel.add(subPanel, GAPLEFT + subIndent + ", growx, wrap");
        }

        return panel;
    }

    private static String indexDisplayName(String indexShortName) {
        return switch (indexShortName) {
            case "settings" -> "Settings";
            case "sitemap" -> "Sitemap";
            case "findings" -> "Findings";
            case "traffic" -> "Traffic";
            default -> throw new IllegalArgumentException("Unknown index for Fields panel: " + indexShortName);
        };
    }

    private static String indexTooltip(String indexShortName) {
        return switch (indexShortName) {
            case "settings" -> "Configure settings fields exported to the attackframework-tool-burp-settings index.";
            case "sitemap" -> "Configure sitemap fields exported to the attackframework-tool-burp-sitemap index.";
            case "findings" -> "Configure findings (aka issues) fields exported to the attackframework-tool-burp-findings index.";
            case "traffic" -> "Configure traffic fields exported to the attackframework-tool-burp-traffic index.";
            default -> throw new IllegalArgumentException("Unknown index for Fields panel: " + indexShortName);
        };
    }

    /** Configures expand button style (match Data Sources). */
    public static void configureExpandButton(JButton b) {
        ButtonStyles.configureExpandButton(b);
    }

    /** Sets expand button label and sub-panel visibility. */
    public static void setExpanded(JButton expandButton, JPanel subPanel, boolean expanded) {
        expandButton.setText(expanded ? EXPAND_EXPANDED : EXPAND_COLLAPSED);
        subPanel.setVisible(expanded);
    }
}
