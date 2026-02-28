package ai.attackframework.tools.burp.ui.primitives;

import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Stroke;
import java.io.Serial;
import java.io.Serializable;
import java.awt.image.BufferedImage;

import javax.swing.Icon;
import javax.swing.JCheckBox;
import javax.swing.UIManager;

/**
 * Icon for tri-state checkbox: keep the current Look & Feel checkbox rendering for selected/unselected,
 * and render indeterminate as the selected checkbox with a centered horizontal dash overlay.
 */
public final class TriStateCheckBoxIcon implements Icon, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final int DASH_INSET = 4;
    private static final int DASH_STROKE = 3;
    private static final int ERASE_STROKE = 7;

    @Override
    public int getIconWidth() {
        Icon lafIcon = UIManager.getIcon("CheckBox.icon");
        return lafIcon != null ? lafIcon.getIconWidth() : 16;
    }

    @Override
    public int getIconHeight() {
        Icon lafIcon = UIManager.getIcon("CheckBox.icon");
        return lafIcon != null ? lafIcon.getIconHeight() : 16;
    }

    @Override
    public void paintIcon(Component c, Graphics g, int x, int y) {
        if (!(c instanceof JCheckBox cb) || !(cb.getModel() instanceof TriStateCheckBox.TriStateButtonModel model)) {
            return;
        }
        TriStateCheckBox.State state = model.getState();

        Icon lafIcon = UIManager.getIcon("CheckBox.icon");
        if (lafIcon != null) {
            lafIcon.paintIcon(c, g, x, y);
            if (state != TriStateCheckBox.State.INDETERMINATE) {
                return;
            }
        }

        if (state != TriStateCheckBox.State.INDETERMINATE) {
            return;
        }

        Color mark = dashColor(c);
        Color fill = sampledFillColor(lafIcon, c, getIconWidth(), getIconHeight());

        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int w = getIconWidth();
        int h = getIconHeight();
        int yMid = y + (h / 2);
        int x1 = x + DASH_INSET;
        int x2 = x + w - DASH_INSET;

        Stroke old = g2.getStroke();
        if (fill != null) {
            g2.setStroke(new java.awt.BasicStroke(ERASE_STROKE, java.awt.BasicStroke.CAP_ROUND, java.awt.BasicStroke.JOIN_ROUND));
            g2.setColor(fill);
            g2.drawLine(x1, yMid, x2, yMid);
        }

        g2.setStroke(new java.awt.BasicStroke(DASH_STROKE, java.awt.BasicStroke.CAP_ROUND, java.awt.BasicStroke.JOIN_ROUND));
        g2.setColor(mark);
        g2.drawLine(x1, yMid, x2, yMid);
        g2.setStroke(old);

        g2.dispose();
    }

    private static Color dashColor(Component c) {
        Color col = UIManager.getColor("CheckBox.icon.checkmarkColor");
        if (col == null) {
            col = UIManager.getColor("CheckBox.checkmark");
        }
        if (col == null) {
            col = UIManager.getColor("CheckBox.foreground");
        }
        if (col == null) {
            col = c.getForeground();
        }
        return col != null ? col : Color.GRAY;
    }

    private static Color sampledFillColor(Icon lafIcon, Component c, int w, int h) {
        if (lafIcon == null || w <= 0 || h <= 0) {
            return null;
        }
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = img.createGraphics();
        lafIcon.paintIcon(c, g2, 0, 0);
        g2.dispose();

        // Sample a few interior pixels that are unlikely to be part of the checkmark/dash.
        int[][] samples = new int[][] {
                { 2, 2 },
                { w - 3, 2 },
                { 2, h - 3 },
                { w - 3, h - 3 },
                { w / 2, 2 },
                { w / 2, h - 3 }
        };
        for (int[] s : samples) {
            int sx = Math.max(0, Math.min(w - 1, s[0]));
            int sy = Math.max(0, Math.min(h - 1, s[1]));
            int argb = img.getRGB(sx, sy);
            int alpha = (argb >>> 24) & 0xFF;
            if (alpha > 0) {
                return new Color(argb, true);
            }
        }
        return null;
    }
}
