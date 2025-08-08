package ai.attackframework.vectors.sources.burp.ui;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;

public class AboutPanel extends JPanel {

    /**
     * Creates a new AboutPanel.
     */
    public AboutPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        JTextArea aboutText = new JTextArea(
                """
                Attack Framework: Burp Exporter
                This extension exports Burp Suite data into formats usable by data lakes and vector DBs
                as part of the Attack Framework initiative.

                GitHub:
                https://github.com/pS3ud0RAnD0m/attackframework-burp-exporter
                https://github.com/attackframework
                """
        );
        aboutText.setEditable(false);
        aboutText.setLineWrap(true);
        aboutText.setWrapStyleWord(true);
        aboutText.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JScrollPane scrollPane = new JScrollPane(aboutText,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        add(scrollPane, BorderLayout.CENTER);
    }
}
