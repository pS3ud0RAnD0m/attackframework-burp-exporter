package ai.attackframework.tools.burp.ui.text;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;

import javax.swing.JLabel;
import javax.swing.SwingConstants;

/**
 * Shared ✓/✖ validation-indicator styling for compact inline field feedback.
 *
 * <p>The indicator keeps a fixed width so layout does not jitter when the glyph changes, prefers
 * the field font when it can render the symbols, and otherwise falls back to a safe Dialog font.</p>
 */
public final class ValidationIndicator {

    private static final Color GREEN = new Color(0, 153, 0);
    private static final Color RED = new Color(200, 0, 0);

    private ValidationIndicator() {
        // utility
    }

    /** Hides the indicator while keeping sizing and font synchronized with the reference field. */
    public static void hide(JLabel indicator, Font referenceFont) {
        prepare(indicator, referenceFont);
        indicator.setText("");
        indicator.setToolTipText(null);
        indicator.setVisible(false);
    }

    /** Shows the indicator in a valid state with the provided tooltip. */
    public static void good(JLabel indicator, Font referenceFont, String tooltip) {
        prepare(indicator, referenceFont);
        indicator.setForeground(GREEN);
        indicator.setText("✓");
        Tooltips.apply(indicator, tooltip);
        indicator.setVisible(true);
    }

    /** Shows the indicator in an invalid state with the provided tooltip. */
    public static void bad(JLabel indicator, Font referenceFont, String tooltip) {
        prepare(indicator, referenceFont);
        indicator.setForeground(RED);
        indicator.setText("✖");
        Tooltips.apply(indicator, tooltip);
        indicator.setVisible(true);
    }

    private static void prepare(JLabel indicator, Font referenceFont) {
        syncFont(indicator, referenceFont);
        fixWidth(indicator);
        indicator.setHorizontalAlignment(SwingConstants.CENTER);
        indicator.setOpaque(false);
    }

    private static void syncFont(JLabel indicator, Font referenceFont) {
        Font current = indicator.getFont();
        if (referenceFont != null && canRenderSymbols(referenceFont)) {
            if (!referenceFont.equals(current)) {
                indicator.setFont(referenceFont);
            }
            return;
        }
        if (current == null || !canRenderSymbols(current)) {
            indicator.setFont(new Font("Dialog", Font.PLAIN, deriveFontSize(referenceFont, current)));
        }
    }

    private static int deriveFontSize(Font referenceFont, Font currentFont) {
        if (referenceFont != null) {
            return referenceFont.getSize();
        }
        if (currentFont != null) {
            return currentFont.getSize();
        }
        return 12;
    }

    private static boolean canRenderSymbols(Font font) {
        return font.canDisplay('✓') && font.canDisplay('✖');
    }

    private static void fixWidth(JLabel indicator) {
        FontMetrics metrics = indicator.getFontMetrics(indicator.getFont());
        int width = Math.max(metrics.stringWidth("✓"), metrics.stringWidth("✖")) + metrics.charWidth(' ');
        int height = metrics.getHeight();
        Dimension size = new Dimension(width, height);
        Dimension preferred = indicator.getPreferredSize();
        if (preferred == null || preferred.width != size.width || preferred.height != size.height) {
            indicator.setMinimumSize(size);
            indicator.setPreferredSize(size);
        }
    }
}
