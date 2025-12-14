package ai.attackframework.tools.burp.ui.primitives;

import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import java.awt.Component;

/**
 * Helpers for consistent scroll pane creation and configuration.
 *
 * <p>EDT: callers must invoke on the EDT.</p>
 */
public final class ScrollPanes {

    private ScrollPanes() {}

    /**
     * Wraps a component in a scroll pane with consistent scrollbar policy and speed.
     *
     * @param view child component to wrap
     * @return configured scroll pane
     */
    public static JScrollPane wrap(Component view) {
        JScrollPane sp = new JScrollPane(
                view,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        );
        configureScrollSpeed(sp);
        return sp;
    }

    /**
     * Standardizes scroll speed for both axes to improve usability across panels.
     *
     * @param sp target scroll pane
     */
    public static void configureScrollSpeed(JScrollPane sp) {
        JScrollBar v = sp.getVerticalScrollBar();
        if (v != null) {
            v.setUnitIncrement(24);
            v.setBlockIncrement(240);
        }
        JScrollBar h = sp.getHorizontalScrollBar();
        if (h != null) {
            h.setUnitIncrement(24);
            h.setBlockIncrement(240);
        }
    }
}
