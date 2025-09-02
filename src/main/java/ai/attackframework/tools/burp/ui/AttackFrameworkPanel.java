package ai.attackframework.tools.burp.ui;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.ScrollPaneConstants;
import java.awt.BorderLayout;
import java.io.Serial;

/**
 * Top-level tabbed UI for the Attack Framework extension.
 *
 * <p>Hosts the Config, Log, Stats, and About panels in a single {@link JTabbedPane}.</p>
 */
public class AttackFrameworkPanel extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    public AttackFrameworkPanel() {
        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();

        tabbedPane.addTab("Config", new JScrollPane(
                new ConfigPanel(),
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED));

        tabbedPane.addTab("Log", new JScrollPane(
                new LogPanel(),
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED));

        tabbedPane.addTab("Stats", new JScrollPane(
                new StatsPanel(),
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED));

        tabbedPane.addTab("About", new JScrollPane(
                new AboutPanel(),
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED));

        add(tabbedPane, BorderLayout.CENTER);
    }
}
