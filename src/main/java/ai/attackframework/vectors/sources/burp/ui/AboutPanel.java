package ai.attackframework.vectors.sources.burp.ui;

import javax.swing.*;
import java.awt.*;

public class AboutPanel extends JPanel {
    public AboutPanel() {
        setLayout(new BorderLayout());
        JTextArea aboutText = new JTextArea(
                """
                        Attack Framework: Burp Exporter\s
                        https://github.com/pS3ud0RAnD0m/attack-framework-burp-exporter
                        
                        This extension exports Burp Suite data into formats usable by data lakes and vector DBs as part of the Attack Framework™ initiative."""
        );
        aboutText.setEditable(false);
        aboutText.setLineWrap(true);
        aboutText.setWrapStyleWord(true);
        add(aboutText, BorderLayout.CENTER);
    }
}
