package ai.attackframework.tools.burp.ui;

import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.ToolTipManager;
import java.awt.BorderLayout;
import java.awt.Component;
import java.io.Serial;

/**
 * Top-level tabbed UI for the Attack Framework extension.
 *
 * <p>Hosts the Config, Log, Stats, and About panels in a single {@link JTabbedPane}.</p>
 */
public class AttackFrameworkPanel extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Constructs the top-level tab container for the extension.
     *
     * <p>Caller must invoke on the EDT. Configures tooltip dismiss delay and mounts all major
     * panels inside a {@link JTabbedPane} wrapped with scroll panes.</p>
     */
    public AttackFrameworkPanel() {
        setLayout(new BorderLayout());

        ToolTipManager.sharedInstance().setDismissDelay(10_000);

        JTabbedPane tabbedPane = new JTabbedPane();

        tabbedPane.addTab("Config", makeScrollPane(new ConfigPanel()));
        tabbedPane.addTab("Log",    makeScrollPane(new LogPanel()));
        tabbedPane.addTab("Stats",  makeScrollPane(new StatsPanel()));
        tabbedPane.addTab("About",  makeScrollPane(new AboutPanel()));

        add(tabbedPane, BorderLayout.CENTER);
    }

    /**
     * Wraps a component in a scroll pane with consistent scrollbar policy and speed.
     *
     * @param view child component to wrap
     * @return configured scroll pane
     */
    private static JScrollPane makeScrollPane(Component view) {
        JScrollPane sp = new JScrollPane(
                view,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        );
        configureScrollSpeed(sp);
        return sp;
    }

    /**
     * Standardizes scroll speed for both axes to improve usability across tabs.
     *
     * <p>
     * @param sp target scroll pane
     */
    private static void configureScrollSpeed(JScrollPane sp) {
        JScrollBar v = sp.getVerticalScrollBar();
        if (v != null) {
            v.setUnitIncrement(24);
            v.setBlockIncrement(240);
        }
        JScrollBar h = sp.getHorizontalScrollBar();
        if (h != null) {
            h.setUnitIncrement(24);
            h.setBlockIncrement(240);
        }
    }
}
