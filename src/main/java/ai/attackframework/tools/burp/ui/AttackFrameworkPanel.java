package ai.attackframework.tools.burp.ui;

import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.ScrollPaneConstants;
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

    public AttackFrameworkPanel() {
        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();

        tabbedPane.addTab("Config", makeScrollPane(new ConfigPanel()));
        tabbedPane.addTab("Log",    makeScrollPane(new LogPanel()));
        tabbedPane.addTab("Stats",  makeScrollPane(new StatsPanel()));
        tabbedPane.addTab("About",  makeScrollPane(new AboutPanel()));

        add(tabbedPane, BorderLayout.CENTER);
    }

    private static JScrollPane makeScrollPane(Component view) {
        JScrollPane sp = new JScrollPane(
                view,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        );
        configureScrollSpeed(sp);
        return sp;
    }

    /** Standardized, comfortable scrolling across all tabs. */
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
