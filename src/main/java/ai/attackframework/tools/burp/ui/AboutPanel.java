package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.Version;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;

public class AboutPanel extends JPanel {

    /** Creates a new AboutPanel. */
    public AboutPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        String version = Version.get();
        JTextArea aboutText = buildAboutText(version);

        JScrollPane scrollPane = new JScrollPane(
                aboutText,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        );

        add(scrollPane, BorderLayout.CENTER);
    }

    /** Builds the static about text area. */
    private static JTextArea buildAboutText(String version) {
        String text = """

                Attack Framework: Burp Exporter v""" + version + """

                This extension exports Burp Suite data into formats usable by data lakes and vector DBs
                as part of the Attack Framework initiative.

                GitHub:
                https://github.com/pS3ud0RAnD0m/attackframework-burp-exporter
                https://github.com/attackframework
                """;

        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(new Font("Monospaced", Font.PLAIN, 12));
        return area;
    }
}
