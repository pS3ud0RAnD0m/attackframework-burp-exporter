package ai.attackframework.tools.burp.ui.primitives;

import javax.swing.JTextField;
import java.awt.Dimension;
import java.awt.FontMetrics;

/**
 * Text field whose preferred width tracks its content length within clamped bounds.
 *
 * <p>EDT: sizing is queried on the EDT by Swing.</p>
 */
public final class AutoSizingTextField extends JTextField {

    private static final int MIN_W = 80;
    private static final int MAX_W = 900;
    private static final int PADDING = 20;

    public AutoSizingTextField(String text) {
        super(text);
    }

    @Override
    public Dimension getPreferredSize() {
        FontMetrics fm = getFontMetrics(getFont());
        int textWidth = fm.stringWidth(getText()) + PADDING;
        int height = super.getPreferredSize().height;
        int w = Math.clamp(textWidth, MIN_W, MAX_W);
        return new Dimension(w, height);
    }
}
