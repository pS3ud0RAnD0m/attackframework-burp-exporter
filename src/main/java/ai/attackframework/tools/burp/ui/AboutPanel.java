package ai.attackframework.tools.burp.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.UIManager;

import ai.attackframework.tools.burp.ui.primitives.ScrollPanes;
import ai.attackframework.tools.burp.utils.Version;
import net.miginfocom.swing.MigLayout;

public class AboutPanel extends JPanel {

    /** Creates a new AboutPanel. */
    public AboutPanel() {
        setLayout(new BorderLayout());

        String version = Version.get();
        JPanel content = buildContent(version);

        add(ScrollPanes.wrapNoHorizontalScroll(content), BorderLayout.CENTER);
    }

    private static JPanel buildContent(String version) {
        JPanel panel = new JPanel(new MigLayout("insets 12, wrap 1, fillx", "[grow,left]"));
        panel.setOpaque(true);
        panel.setBackground(UIManager.getColor("Panel.background"));

        Font labelFont = UIManager.getFont("Label.font");

        JLabel header = new JLabel("Attack Framework: Burp Exporter v" + version);
        header.setFont(labelFont.deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        JTextArea area = new JTextArea("""
                This Burp Suite extension continuously exports settings, sitemap, issues, and traffic into OpenSearch for embedding into vector databases to support agentic penetration testing.
                """);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setFont(labelFont);
        area.setForeground(UIManager.getColor("Label.foreground"));
        panel.add(area, "growx, wrap");

        panel.add(buildLinkRow("Burp Exporter:", "https://github.com/pS3ud0RAnD0m/attackframework-burp-exporter"), "growx, wrap");
        panel.add(buildLinkRow("Attack Framework:", "https://github.com/attackframework/attackframework"), "growx");
        return panel;
    }

    private static JPanel buildLinkRow(String labelText, String url) {
        Font labelFont = UIManager.getFont("Label.font");
        JPanel row = new JPanel(new MigLayout("insets 0, gapx 6", "[][grow,left]", "[]"));
        row.setOpaque(false);

        JLabel label = new JLabel(labelText);
        label.setFont(labelFont.deriveFont(Math.max(11f, labelFont.getSize2D() - 1f)));
        label.setForeground(UIManager.getColor("Label.foreground"));

        JLabel urlLabel = new JLabel(url);
        urlLabel.setFont(labelFont.deriveFont(Math.max(11f, labelFont.getSize2D() - 1f)));
        urlLabel.setForeground(readableLinkColor(defaultColor(UIManager.getColor("Panel.background"), Color.WHITE)));
        urlLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        urlLabel.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                openLink(url);
            }
        });

        row.add(label);
        row.add(urlLabel, "growx");
        return row;
    }

    private static Color defaultColor(Color color, Color fallback) {
        return color != null ? color : fallback;
    }

    private static Color readableLinkColor(Color background) {
        Color configured = UIManager.getColor("Component.linkColor");
        if (configured == null) {
            configured = UIManager.getColor("Link.foreground");
        }
        if (configured != null && contrastRatio(configured, background) >= 3.0) {
            return configured;
        }
        return isDark(background) ? new Color(120, 170, 255) : new Color(0, 102, 204);
    }

    private static boolean isDark(Color color) {
        return luminance(color) < 0.5;
    }

    private static double contrastRatio(Color left, Color right) {
        double lighter = Math.max(luminance(left), luminance(right));
        double darker = Math.min(luminance(left), luminance(right));
        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double luminance(Color color) {
        double red = channel(color.getRed());
        double green = channel(color.getGreen());
        double blue = channel(color.getBlue());
        return (0.2126 * red) + (0.7152 * green) + (0.0722 * blue);
    }

    private static double channel(int value) {
        double normalized = value / 255.0;
        return normalized <= 0.03928 ? normalized / 12.92 : Math.pow((normalized + 0.055) / 1.055, 2.4);
    }

    private static void openLink(String url) {
        if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            return;
        }
        try {
            Desktop.getDesktop().browse(java.net.URI.create(url));
        } catch (IOException | IllegalArgumentException ignored) {
        }
    }
}
