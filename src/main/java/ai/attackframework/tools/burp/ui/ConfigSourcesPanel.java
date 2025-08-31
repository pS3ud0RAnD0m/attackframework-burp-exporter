package ai.attackframework.tools.burp.ui;

import net.miginfocom.swing.MigLayout;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Component;
import java.awt.Font;
import java.util.Objects;

/**
 * Builds the "Data Sources" section panel used by ConfigPanel.
 * State (checkbox instances and component names) is owned by ConfigPanel
 * and injected here to keep a single source of truth.
 */
public record ConfigSourcesPanel(
        JCheckBox settingsCheckbox,
        JCheckBox sitemapCheckbox,
        JCheckBox issuesCheckbox,
        JCheckBox trafficCheckbox,
        int indentPx
) {
    private static final String GAPLEFT = "gapleft ";

    public ConfigSourcesPanel {
        Objects.requireNonNull(settingsCheckbox, "settingsCheckbox");
        Objects.requireNonNull(sitemapCheckbox,  "sitemapCheckbox");
        Objects.requireNonNull(issuesCheckbox,   "issuesCheckbox");
        Objects.requireNonNull(trafficCheckbox,  "trafficCheckbox");
    }

    /**
     * Returns a panel containing the header and four data-source checkboxes.
     * Layout matches the original implementation for visual consistency.
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = new JLabel("Data Sources");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        panel.add(settingsCheckbox, GAPLEFT + indentPx);
        panel.add(sitemapCheckbox,  GAPLEFT + indentPx);
        panel.add(issuesCheckbox,   GAPLEFT + indentPx);
        panel.add(trafficCheckbox,  GAPLEFT + indentPx);

        return panel;
    }
}
