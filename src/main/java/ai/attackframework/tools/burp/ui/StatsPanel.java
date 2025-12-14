package ai.attackframework.tools.burp.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;

import javax.swing.JPanel;
import javax.swing.JTextArea;

import ai.attackframework.tools.burp.ui.primitives.ScrollPanes;

public class StatsPanel extends JPanel {

    /**
     * Creates the Stats panel placeholder.
     *
     * <p>Caller must invoke on the EDT. Content is placeholder text until stats are implemented.</p>
     */
    public StatsPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        JTextArea statsArea = new JTextArea("\nStats coming soon...");
        statsArea.setEditable(false);
        statsArea.setLineWrap(true);
        statsArea.setWrapStyleWord(true);
        statsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        add(ScrollPanes.wrap(statsArea), BorderLayout.CENTER);
    }
}
