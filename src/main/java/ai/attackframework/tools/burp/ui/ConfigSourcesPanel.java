package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Font;
import java.util.Objects;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Data Sources" section panel used by ConfigPanel.
 * State (checkbox instances and component names) is owned by ConfigPanel
 * and injected here to keep a single source of truth.
 * Sections Settings, Issues, and Traffic have collapsible sub-checkboxes.
 */
public final class ConfigSourcesPanel {

    private final JCheckBox settingsCheckbox;
    private final JCheckBox sitemapCheckbox;
    private final JCheckBox issuesCheckbox;
    private final JCheckBox trafficCheckbox;
    private final JButton settingsExpandButton;
    private final JPanel settingsSubPanel;
    private final JButton issuesExpandButton;
    private final JPanel issuesSubPanel;
    private final JButton trafficExpandButton;
    private final JPanel trafficSubPanel;
    private final int indentPx;
    private static final String GAPLEFT = "gapleft ";

    public ConfigSourcesPanel(JCheckBox settingsCheckbox,
                              JCheckBox sitemapCheckbox,
                              JCheckBox issuesCheckbox,
                              JCheckBox trafficCheckbox,
                              JButton settingsExpandButton,
                              JPanel settingsSubPanel,
                              JButton issuesExpandButton,
                              JPanel issuesSubPanel,
                              JButton trafficExpandButton,
                              JPanel trafficSubPanel,
                              int indentPx) {
        this.settingsCheckbox = Objects.requireNonNull(settingsCheckbox, "settingsCheckbox");
        this.sitemapCheckbox = Objects.requireNonNull(sitemapCheckbox, "sitemapCheckbox");
        this.issuesCheckbox = Objects.requireNonNull(issuesCheckbox, "issuesCheckbox");
        this.trafficCheckbox = Objects.requireNonNull(trafficCheckbox, "trafficCheckbox");
        this.settingsExpandButton = Objects.requireNonNull(settingsExpandButton, "settingsExpandButton");
        this.settingsSubPanel = Objects.requireNonNull(settingsSubPanel, "settingsSubPanel");
        this.issuesExpandButton = Objects.requireNonNull(issuesExpandButton, "issuesExpandButton");
        this.issuesSubPanel = Objects.requireNonNull(issuesSubPanel, "issuesSubPanel");
        this.trafficExpandButton = Objects.requireNonNull(trafficExpandButton, "trafficExpandButton");
        this.trafficSubPanel = Objects.requireNonNull(trafficSubPanel, "trafficSubPanel");
        this.indentPx = indentPx;
    }

    /**
     * Builds the Data Sources section with the four source checkboxes and
     * collapsible sub-rows for Settings, Issues, and Traffic.
     *
     * <p>Caller must invoke on the EDT. Sub-panels start collapsed.</p>
     *
     * @return assembled panel containing header and source checkboxes
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1, hidemode 3", "[left]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = new JLabel("Data Sources");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        int subIndent = indentPx * 2;

        // Settings: main checkbox + inline +/-; then sub-panel (collapsed)
        panel.add(parentRow(settingsCheckbox, settingsExpandButton, indentPx), "wrap");
        panel.add(settingsSubPanel, GAPLEFT + subIndent + ", wrap");

        panel.add(sitemapCheckbox, GAPLEFT + indentPx);

        // Issues: main checkbox + inline +/-; then sub-panel
        panel.add(parentRow(issuesCheckbox, issuesExpandButton, indentPx), "wrap");
        panel.add(issuesSubPanel, GAPLEFT + subIndent + ", wrap");

        // Traffic: main checkbox + inline +/-; then sub-panel
        panel.add(parentRow(trafficCheckbox, trafficExpandButton, indentPx), "wrap");
        panel.add(trafficSubPanel, GAPLEFT + subIndent + ", wrap");

        return panel;
    }

    private JPanel parentRow(JCheckBox parent, JButton expandButton, int indentPx) {
        JPanel row = new JPanel(new MigLayout("insets 0, aligny center", "[left]6[pref!]"));
        row.setOpaque(false);
        row.add(parent, GAPLEFT + indentPx + ", aligny center");
        row.add(expandButton, "aligny center");
        return row;
    }
}
