package ai.attackframework.tools.burp.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.UIManager;

import ai.attackframework.tools.burp.ui.text.Tooltips;
import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Burp Suite Sources" section panel used by ConfigPanel.
 * State (checkbox instances and component names) is owned by ConfigPanel
 * and injected here to keep a single source of truth.
 * Sections Settings, Issues, and Traffic have collapsible sub-checkboxes.
 */
public final class ConfigSourcesPanel {
    private static final String COMMUNITY_ICON_TOOLTIP = Tooltips.html("Unsupported in Community Edition.");
    private static final Icon COMMUNITY_NOTICE_ICON = new CommunityEditionInfoIcon();

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
    private final JComponent issuesCommunityIndicator;
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
                              JComponent issuesCommunityIndicator,
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
        this.issuesCommunityIndicator = issuesCommunityIndicator;
        this.indentPx = indentPx;
    }

    static JPanel buildCommunityEditionIndicator(String panelName, String iconName) {
        JPanel indicator = new JPanel(new MigLayout("insets 0, aligny center, hidemode 3", "[pref!]"));
        indicator.setOpaque(false);
        indicator.setName(panelName);
        indicator.setVisible(false);

        JLabel iconLabel = new Tooltips.HtmlLabel("");
        iconLabel.setName(iconName);
        iconLabel.setIcon(COMMUNITY_NOTICE_ICON);
        iconLabel.setOpaque(false);
        iconLabel.setToolTipText(COMMUNITY_ICON_TOOLTIP);

        indicator.add(iconLabel);
        return indicator;
    }

    /**
     * Builds the Burp Suite Sources section with the four source checkboxes and
     * collapsible sub-rows for Settings, Issues, and Traffic.
     *
     * <p>Caller must invoke on the EDT. Sub-panels start collapsed.</p>
     *
     * @return assembled panel containing header and source checkboxes
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1, hidemode 3", "[left]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = Tooltips.label("Burp Suite Sources",
                Tooltips.html("Configure the Burp Suite sources of data for export."));
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        int subIndent = indentPx * 2;

        // Settings: main checkbox + inline +/-; then sub-panel (collapsed)
        panel.add(parentRow(settingsCheckbox, settingsExpandButton, null, indentPx), "wrap");
        panel.add(settingsSubPanel, GAPLEFT + subIndent + ", wrap");

        panel.add(sitemapCheckbox, GAPLEFT + indentPx);

        // Issues: main checkbox + inline +/-; then sub-panel
        panel.add(parentRow(issuesCheckbox, issuesExpandButton, issuesCommunityIndicator, indentPx), "wrap");
        panel.add(issuesSubPanel, GAPLEFT + subIndent + ", wrap");

        // Traffic: main checkbox + inline +/-; then sub-panel
        panel.add(parentRow(trafficCheckbox, trafficExpandButton, null, indentPx), "wrap");
        panel.add(trafficSubPanel, GAPLEFT + subIndent + ", wrap");

        return panel;
    }

    private JPanel parentRow(JCheckBox parent, JButton expandButton, JComponent communityNotice, int indentPx) {
        JPanel row = new JPanel(new MigLayout("insets 0, aligny center, hidemode 3", "[left]6[pref!]12[pref]"));
        row.setOpaque(false);
        row.add(parent, GAPLEFT + indentPx + ", aligny center");
        row.add(expandButton, "aligny center");
        if (communityNotice != null) {
            row.add(communityNotice, "aligny center, hidemode 3");
        }
        return row;
    }

    private static final class CommunityEditionInfoIcon implements Icon, Serializable {
        @Serial private static final long serialVersionUID = 1L;
        private static final int SIZE = 12;

        @Override
        public void paintIcon(Component component, Graphics graphics, int x, int y) {
            Graphics2D g2 = (Graphics2D) graphics.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                Color blue = UIManager.getColor("Component.linkColor");
                if (blue == null) {
                    blue = UIManager.getColor("Link.foreground");
                }
                if (blue == null) {
                    blue = new Color(0, 102, 204);
                }
                g2.setColor(blue);
                g2.fillOval(x, y, SIZE, SIZE);
                g2.setColor(Color.WHITE);
                Font font = component.getFont();
                if (font == null) {
                    font = UIManager.getFont("Label.font");
                }
                if (font == null) {
                    font = new JLabel().getFont();
                }
                g2.setFont(font.deriveFont(Font.BOLD, 9f));
                FontMetrics metrics = g2.getFontMetrics();
                String text = "!";
                int textX = x + (SIZE - metrics.stringWidth(text)) / 2;
                int textY = y + ((SIZE - metrics.getHeight()) / 2) + metrics.getAscent() - 1;
                g2.drawString(text, textX, textY);
            } finally {
                g2.dispose();
            }
        }

        @Override
        public int getIconWidth() {
            return SIZE;
        }

        @Override
        public int getIconHeight() {
            return SIZE;
        }
    }
}
