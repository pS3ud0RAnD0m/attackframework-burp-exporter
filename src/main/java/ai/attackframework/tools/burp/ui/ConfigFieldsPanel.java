package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Font;
import java.util.Map;
import java.util.Objects;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import ai.attackframework.tools.burp.ui.primitives.ButtonStyles;
import ai.attackframework.tools.burp.ui.text.Tooltips;
import ai.attackframework.tools.burp.utils.config.ExportFieldRegistry;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Index Fields" section used by {@link ConfigPanel}.
 *
 * <p>Each index is rendered as an expandable group of toggleable export-field checkboxes. The
 * layout wraps so all controls remain visible when a section expands.</p>
 */
public final class ConfigFieldsPanel {

    private static final String EXPAND_COLLAPSED = "+";
    private static final String EXPAND_EXPANDED = "−";
    private static final String GAPLEFT = "gapleft ";

    private final Map<String, JButton> expandButtonsByIndex;
    private final Map<String, JPanel> subPanelsByIndex;
    private final int indentPx;

    public ConfigFieldsPanel(
            Map<String, JButton> expandButtonsByIndex,
            Map<String, JPanel> subPanelsByIndex,
            int indentPx) {
        this.expandButtonsByIndex = Objects.requireNonNull(expandButtonsByIndex);
        this.subPanelsByIndex = Objects.requireNonNull(subPanelsByIndex);
        this.indentPx = indentPx;
    }

    /**
     * Builds the Index Fields panel.
     *
     * <p>Caller must invoke on the EDT. Sub-panels start collapsed. When
     * {@code sectionHeaderRowsOut} is non-null, this method fills it with the header row for each
     * index so callers can enable or disable entire sections.</p>
     *
     * @param sectionHeaderRowsOut optional destination for index-name to header-row mappings
     * @return assembled panel containing the section header and per-index groups
     */
    public JPanel build(java.util.Map<String, JPanel> sectionHeaderRowsOut) {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1, hidemode 3", "[grow,left]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = Tooltips.label("Index Fields",
                Tooltips.html(
                        "Configure which mapped fields each exported document includes.",
                        "These toggles affect document contents, not index creation."
                ));
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6, wrap");

        int subIndent = indentPx * 2;

        for (String indexName : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            JButton expandBtn = expandButtonsByIndex.get(indexName);
            JPanel subPanel = subPanelsByIndex.get(indexName);
            if (expandBtn == null || subPanel == null) continue;

            String displayName = indexDisplayName(indexName);
            JLabel indexLabel = Tooltips.label(displayName, indexTooltip(indexName));
            Tooltips.apply(expandBtn, indexExpandTooltip(indexName));

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
            case "tool" -> "Tool";
            default -> throw new IllegalArgumentException("Unknown index for Fields panel: " + indexShortName);
        };
    }

    private static String indexTooltip(String indexShortName) {
        return switch (indexShortName) {
            case "settings" -> Tooltips.htmlRaw(
                    "<b>Settings fields</b>",
                    "Configure fields exported to <code>attackframework-tool-burp-settings</code>.",
                    "Use these toggles to trim the settings document payload."
            );
            case "sitemap" -> Tooltips.htmlRaw(
                    "<b>Sitemap fields</b>",
                    "Configure fields exported to <code>attackframework-tool-burp-sitemap</code>.",
                    "Field names follow the request/response document shape."
            );
            case "findings" -> findingsTooltip();
            case "traffic" -> Tooltips.htmlRaw(
                    "<b>Traffic fields</b>",
                    "Configure fields exported to <code>attackframework-tool-burp-traffic</code>.",
                    "Traffic field labels are shown hierarchically to match the mapped document shape."
            );
            case "tool" -> Tooltips.htmlRaw(
                    "<b>Tool fields</b>",
                    "Configure fields exported to <code>attackframework-tool-burp</code>.",
                    "These fields cover Burp Exporter logs, runtime stats snapshots, and config snapshots."
            );
            default -> throw new IllegalArgumentException("Unknown index for Fields panel: " + indexShortName);
        };
    }

    private static String indexExpandTooltip(String indexShortName) {
        return switch (indexShortName) {
            case "settings" -> Tooltips.html("Show or hide Settings field options.");
            case "sitemap" -> Tooltips.html("Show or hide Sitemap field options.");
            case "findings" -> findingsExpandTooltip();
            case "traffic" -> Tooltips.html("Show or hide Traffic field options.");
            case "tool" -> Tooltips.html("Show or hide Tool field options.");
            default -> throw new IllegalArgumentException("Unknown index for Fields panel: " + indexShortName);
        };
    }

    private static String findingsTooltip() {
        if (RuntimeConfig.isCommunityEdition()) {
            return Tooltips.html("Unsupported in Community Edition.");
        }
        return Tooltips.html("All findings (aka issues) fields.");
    }

    private static String findingsExpandTooltip() {
        if (RuntimeConfig.isCommunityEdition()) {
            return Tooltips.html("Unsupported in Community Edition.");
        }
        return Tooltips.html("Show or hide fields for all findings (aka issues).");
    }

    /** Configures the shared expand-button style used in the sources and fields sections. */
    public static void configureExpandButton(JButton b) {
        ButtonStyles.configureExpandButton(b);
    }

    /** Updates the expand button label and the matching sub-panel visibility. */
    public static void setExpanded(JButton expandButton, JPanel subPanel, boolean expanded) {
        expandButton.setText(expanded ? EXPAND_EXPANDED : EXPAND_COLLAPSED);
        subPanel.setVisible(expanded);
    }
}
