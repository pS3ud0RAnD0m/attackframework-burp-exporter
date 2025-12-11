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
public final class ConfigSourcesPanel {

    private final JCheckBox settingsCheckbox;
    private final JCheckBox sitemapCheckbox;
    private final JCheckBox issuesCheckbox;
    private final JCheckBox trafficCheckbox;
    private final int indentPx;
    private static final String GAPLEFT = "gapleft ";

    public ConfigSourcesPanel(JCheckBox settingsCheckbox,
                              JCheckBox sitemapCheckbox,
                              JCheckBox issuesCheckbox,
                              JCheckBox trafficCheckbox,
                              int indentPx) {
        this.settingsCheckbox = Objects.requireNonNull(settingsCheckbox, "settingsCheckbox");
        this.sitemapCheckbox = Objects.requireNonNull(sitemapCheckbox, "sitemapCheckbox");
        this.issuesCheckbox = Objects.requireNonNull(issuesCheckbox, "issuesCheckbox");
        this.trafficCheckbox = Objects.requireNonNull(trafficCheckbox, "trafficCheckbox");
        this.indentPx = indentPx;
    }

    /**
     * Builds the Data Sources section with the four source checkboxes.
     *
     * <p>Caller must invoke on the EDT. Layout matches the original for visual consistency.</p>
     *
     * @return assembled panel containing header and source checkboxes
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
