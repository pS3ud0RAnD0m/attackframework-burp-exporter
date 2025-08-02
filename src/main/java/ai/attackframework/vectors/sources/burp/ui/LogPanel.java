package ai.attackframework.vectors.sources.burp.ui;

import ai.attackframework.vectors.sources.burp.utils.Logger;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LogPanel extends JPanel implements Logger.LogListener {

    private final JTextPane logTextPane;
    private final StyledDocument doc;
    private final Style infoStyle;
    private final Style errorStyle;
    private final DateTimeFormatter timestampFormat;

    public LogPanel() {
        setLayout(new BorderLayout());

        logTextPane = new JTextPane();
        logTextPane.setEditable(false);
        logTextPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logTextPane.setBackground(UIManager.getColor("TextPane.background"));
        logTextPane.setForeground(UIManager.getColor("TextPane.foreground"));

        doc = logTextPane.getStyledDocument();
        timestampFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        infoStyle = doc.addStyle("INFO", null);
        StyleConstants.setForeground(infoStyle, UIManager.getColor("TextPane.foreground"));

        errorStyle = doc.addStyle("ERROR", null);
        StyleConstants.setForeground(errorStyle, UIManager.getColor("TextPane.foreground"));
        StyleConstants.setBold(errorStyle, true);

        JScrollPane scrollPane = new JScrollPane(logTextPane);
        add(scrollPane, BorderLayout.CENTER);

        Logger.registerListener(this);
    }

    @Override
    public void onLog(String level, String message) {
        SwingUtilities.invokeLater(() -> {
            try {
                String timestamp = "[" + timestampFormat.format(LocalDateTime.now()) + "]";
                String formatted = String.format("%s [%s] %s%n", timestamp, level, message);
                doc.insertString(doc.getLength(), formatted,
                        "ERROR".equalsIgnoreCase(level) ? errorStyle : infoStyle);
                logTextPane.setCaretPosition(doc.getLength());
            } catch (BadLocationException e) {
                System.err.println("Failed to append log to LogPanel: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        });
    }
}
