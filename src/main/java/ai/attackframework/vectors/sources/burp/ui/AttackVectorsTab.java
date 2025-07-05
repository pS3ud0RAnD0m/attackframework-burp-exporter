package ai.attackframework.vectors.sources.burp.ui;

import javax.swing.*;
import java.awt.*;

public class AttackVectorsTab extends JPanel {

    public AttackVectorsTab() {
        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();

        tabbedPane.addTab("Config", new ConfigPanel());
        tabbedPane.addTab("Stats", new StatsPanel());
        tabbedPane.addTab("Logs", new LogsPanel());
        tabbedPane.addTab("About", new AboutPanel());

        add(tabbedPane, BorderLayout.CENTER);
    }
}
