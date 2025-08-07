package ai.attackframework.vectors.sources.burp.ui;

import javax.swing.*;
import java.awt.*;

public class ExporterTab extends JPanel {

    public ExporterTab() {
        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();

        tabbedPane.addTab("Config", new JScrollPane(new ConfigPanel(),
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED));

        tabbedPane.addTab("Stats", new JScrollPane(new StatsPanel(),
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED));

        tabbedPane.addTab("Log", new JScrollPane(new LogPanel(),
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED));

        tabbedPane.addTab("About", new JScrollPane(new AboutPanel(),
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED));

        add(tabbedPane, BorderLayout.CENTER);
    }
}
