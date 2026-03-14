package ai.attackframework.tools.burp.ui.primitives;

import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.awt.Insets;

import javax.swing.JButton;
import javax.swing.UIManager;

/**
 * Shared button styling helpers for consistent button width and text weight.
 */
public final class ButtonStyles {

    private static final float EXPAND_BUTTON_SIZE = 22f;

    private ButtonStyles() {
        // utility class
    }

    /**
     * Narrows a button by reducing left/right padding while keeping vertical padding,
     * and forces plain (non-bold) font.
     */
    public static void normalize(JButton button) {
        if (button == null) {
            return;
        }
        Insets margin = button.getMargin();
        if (margin != null) {
            Insets lafMargin = UIManager.getInsets("Button.margin");
            int lafSide = lafMargin != null
                    ? Math.max(lafMargin.left, lafMargin.right)
                    : Math.max(margin.left, margin.right);
            int side = margin.top + Math.max(0, (lafSide - margin.top) / 2);
            button.setMargin(new Insets(margin.top, side, margin.bottom, side));
        }
        Font font = button.getFont();
        if (font != null && font.getStyle() != Font.PLAIN) {
            button.setFont(font.deriveFont(Font.PLAIN));
        }
    }

    /**
     * Recursively normalizes all JButton instances in a component tree.
     */
    public static void normalizeTree(Component root) {
        if (root == null) {
            return;
        }
        if (root instanceof JButton button) {
            normalize(button);
        }
        if (root instanceof Container container) {
            for (Component child : container.getComponents()) {
                normalizeTree(child);
            }
        }
    }

    /**
     * Applies styling for compact expand/collapse glyph buttons.
     */
    public static void configureExpandButton(JButton button) {
        if (button == null) {
            return;
        }
        button.setBorderPainted(false);
        button.setContentAreaFilled(false);
        button.setFocusPainted(false);
        button.setOpaque(false);
        button.setMargin(new Insets(0, 0, 0, 0));
        button.setFocusable(false);
        Font font = button.getFont();
        if (font != null) {
            button.setFont(font.deriveFont(Font.PLAIN, EXPAND_BUTTON_SIZE));
        }
    }
}
