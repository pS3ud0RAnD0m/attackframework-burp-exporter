package ai.attackframework.tools.burp.ui.primitives;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import java.awt.Color;
import java.awt.Font;
import java.util.Objects;

/**
 * Helpers for status-area configuration and message updates.
 *
 * <p>EDT: callers must invoke on the EDT.</p>
 */
public final class StatusViews {

    private StatusViews() {}

    /** Configures a status {@link JTextArea} for compact, monospaced, non-editable output. */
    public static void configureTextArea(JTextArea area) {
        area.setEditable(false);
        area.setLineWrap(false);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setFont(new Font("Monospaced", Font.PLAIN, 12));
        area.setRows(1);
        area.setColumns(1);
    }

    /**
     * Configures a wrapper panel around a status area for compact bordered output.
     *
     * <p>EDT: caller must invoke on the EDT.</p>
     *
     * @param wrapper container that hosts the status area
     * @param area    configured status text area
     */
    public static void configureWrapper(JPanel wrapper, JTextArea area) {
        Objects.requireNonNull(wrapper, "wrapper");
        Objects.requireNonNull(area, "area");
        wrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        wrapper.removeAll();
        wrapper.add(area, "w pref!");
        wrapper.setVisible(false);
    }

    /**
     * Updates text and sizes the status area & wrapper to the message content.
     *
     * @param area   the status text area
     * @param wrapper parent wrapper (visibility toggled on update)
     * @param message status message (can be multi-line)
     * @param minCols minimum columns to show
     * @param maxCols maximum columns to clamp to
     */
    public static void setStatus(JTextArea area, JPanel wrapper, String message, int minCols, int maxCols) {
        area.setText(message == null ? "" : message);
        String[] lines = (message == null ? "" : message).split("\r\n|\r|\n", -1);
        int rows = Math.max(lines.length, 1);
        int cols = Math.clamp(maxLineLength(lines), minCols, maxCols);
        area.setRows(rows);
        area.setColumns(cols);
        wrapper.setVisible(true);
        wrapper.revalidate();
        wrapper.repaint();
    }

    private static int maxLineLength(String[] lines) {
        int max = 1;
        for (String s : lines) if (s != null && s.length() > max) max = s.length();
        return max;
    }
}
