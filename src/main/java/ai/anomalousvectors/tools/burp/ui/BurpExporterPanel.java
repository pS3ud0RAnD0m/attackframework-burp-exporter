package ai.anomalousvectors.tools.burp.ui;

import java.awt.BorderLayout;
import java.io.Serial;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import ai.anomalousvectors.tools.burp.ui.primitives.ScrollPanes;

/**
 * Top-level tabbed UI for the Burp Exporter extension.
 * <p>
 * Hosts the Config, Log, Stats, and About panels in a single {@link JTabbedPane}.</p>
 */
public class BurpExporterPanel extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Constructs the top-level tab container for the extension.
     * <p>
     * Caller must invoke on the EDT. Tooltip hover timing is configured once in
     * {@link ai.anomalousvectors.tools.burp.Exporter#initialize}. Mounts all major panels inside a
     * {@link JTabbedPane} wrapped with scroll panes.</p>
     */
    public BurpExporterPanel() {
        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();

        tabbedPane.addTab("Config", ScrollPanes.wrap(new ConfigPanel()));
        tabbedPane.addTab("Log",    ScrollPanes.wrap(new LogPanel()));
        tabbedPane.addTab("Stats",  ScrollPanes.wrap(new StatsPanel()));
        tabbedPane.addTab("About",  ScrollPanes.wrap(new AboutPanel()));

        add(tabbedPane, BorderLayout.CENTER);
    }

}
