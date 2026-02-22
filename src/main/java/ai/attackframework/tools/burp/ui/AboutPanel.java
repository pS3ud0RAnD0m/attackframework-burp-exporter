package ai.attackframework.tools.burp.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;

import javax.swing.JPanel;
import javax.swing.JTextArea;

import ai.attackframework.tools.burp.ui.primitives.ScrollPanes;
import ai.attackframework.tools.burp.utils.Version;

public class AboutPanel extends JPanel {

    /** Creates a new AboutPanel. */
    public AboutPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        String version = Version.get();
        JTextArea aboutText = buildAboutText(version);

        add(ScrollPanes.wrap(aboutText), BorderLayout.CENTER);
    }

    /** Builds the static about text area. */
    private static JTextArea buildAboutText(String version) {
        String text = """

                Attack Framework: Burp Exporter v""" + version + """

                This Burp Suite extension continuously exports settings, sitemap, issues, and traffic into OpenSearch for embedding into vector databases to support agentic penetration testing.

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
