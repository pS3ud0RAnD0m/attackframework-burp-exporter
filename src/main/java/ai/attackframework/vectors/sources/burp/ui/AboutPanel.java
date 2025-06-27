package ai.attackframework.vectors.sources.burp.ui;

import javax.swing.*;
import java.awt.*;

public class AboutPanel extends JPanel {
    public AboutPanel() {
        setLayout(new BorderLayout());
        JTextArea aboutText = new JTextArea(
                "Attack Vectors: Burp Exporter\n" +
                        "https://github.com/attackinc/attackvectors-burp\n\n" +
                        "This extension exports Burp Suite data into formats usable by data lakes and vector DBs.\n" +
                        "Part of the Attack Framework initiative."
        );
        aboutText.setEditable(false);
        aboutText.setLineWrap(true);
        aboutText.setWrapStyleWord(true);
        add(aboutText, BorderLayout.CENTER);
    }
}
