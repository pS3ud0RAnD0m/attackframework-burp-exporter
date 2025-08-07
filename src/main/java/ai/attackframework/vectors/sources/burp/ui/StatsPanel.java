package ai.attackframework.vectors.sources.burp.ui;

import javax.swing.*;
import java.awt.*;

public class StatsPanel extends JPanel {
    public StatsPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        JTextArea statsArea = new JTextArea("Stats coming soon...");
        statsArea.setEditable(false);
        statsArea.setLineWrap(true);
        statsArea.setWrapStyleWord(true);
        statsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JScrollPane scrollPane = new JScrollPane(statsArea,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        add(scrollPane, BorderLayout.CENTER);
    }
}
