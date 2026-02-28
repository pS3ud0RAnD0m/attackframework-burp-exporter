package ai.attackframework.tools.burp.ui.primitives;

import java.awt.image.BufferedImage;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.ui.primitives.TriStateCheckBox.State;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link TriStateCheckBoxIcon}: dimensions and that paintIcon does not throw for each state.
 */
class TriStateCheckBoxIconTest {

    @Test
    void getIconWidth_and_getIconHeight_positive() {
        TriStateCheckBoxIcon icon = new TriStateCheckBoxIcon();
        assertThat(icon.getIconWidth()).isPositive();
        assertThat(icon.getIconHeight()).isPositive();
    }

    @Test
    void paintIcon_doesNotThrow_forSelected() {
        TriStateCheckBox box = new TriStateCheckBox("", State.SELECTED);
        TriStateCheckBoxIcon icon = new TriStateCheckBoxIcon();
        BufferedImage img = new BufferedImage(icon.getIconWidth() + 10, icon.getIconHeight() + 10, BufferedImage.TYPE_INT_ARGB);
        icon.paintIcon(box, img.getGraphics(), 0, 0);
    }

    @Test
    void paintIcon_doesNotThrow_forDeselected() {
        TriStateCheckBox box = new TriStateCheckBox("", State.DESELECTED);
        TriStateCheckBoxIcon icon = new TriStateCheckBoxIcon();
        BufferedImage img = new BufferedImage(icon.getIconWidth() + 10, icon.getIconHeight() + 10, BufferedImage.TYPE_INT_ARGB);
        icon.paintIcon(box, img.getGraphics(), 0, 0);
    }

    @Test
    void paintIcon_doesNotThrow_forIndeterminate() {
        TriStateCheckBox box = new TriStateCheckBox("", State.INDETERMINATE);
        TriStateCheckBoxIcon icon = new TriStateCheckBoxIcon();
        BufferedImage img = new BufferedImage(icon.getIconWidth() + 10, icon.getIconHeight() + 10, BufferedImage.TYPE_INT_ARGB);
        icon.paintIcon(box, img.getGraphics(), 0, 0);
    }

    @Test
    void paintIcon_withNonTriStateCheckBox_doesNotThrow() {
        TriStateCheckBoxIcon icon = new TriStateCheckBoxIcon();
        javax.swing.JCheckBox plain = new javax.swing.JCheckBox("x");
        BufferedImage img = new BufferedImage(24, 24, BufferedImage.TYPE_INT_ARGB);
        icon.paintIcon(plain, img.getGraphics(), 0, 0);
    }
}
