package ai.attackframework.tools.burp.ui;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;

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

        JScrollPane scrollPane = new JScrollPane(
                statsArea,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        );

        add(scrollPane, BorderLayout.CENTER);
    }
}
