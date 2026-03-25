package ai.attackframework.tools.burp.ui.primitives;

import javax.swing.JPasswordField;
import javax.swing.JToolTip;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Dimension;
import java.awt.FontMetrics;

import ai.attackframework.tools.burp.ui.text.Tooltips;

/**
 * Password field whose preferred width tracks its content length within clamped bounds.
 * Uses character count only (not actual characters) for sizing.
 *
 * <p>EDT: sizing is queried on the EDT by Swing.</p>
 */
public final class AutoSizingPasswordField extends JPasswordField {

    private static final int MIN_W = 80;
    private static final int MAX_W = 900;
    private static final int PADDING = 20;

    /**
     * Creates an auto-sizing password field.
     */
    public AutoSizingPasswordField() {
        super();
        putClientProperty("html.disable", Boolean.FALSE);
        getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { revalidate(); }

            @Override
            public void removeUpdate(DocumentEvent e) { revalidate(); }

            @Override
            public void changedUpdate(DocumentEvent e) { revalidate(); }
        });
    }

    /**
     * Computes preferred size based on content length (character count), clamped between
     * {@value MIN_W} and {@value MAX_W} with padding.
     *
     * @return preferred dimension reflecting current content length
     */
    @Override
    public Dimension getPreferredSize() {
        FontMetrics fm = getFontMetrics(getFont());
        int len = getPassword() != null ? getPassword().length : 0;
        int avgCharW = fm.charWidth('m');
        int textWidth = len * avgCharW + PADDING;
        int height = super.getPreferredSize().height;
        int w = Math.clamp(textWidth, MIN_W, MAX_W);
        return new Dimension(w, height);
    }

    @Override
    public JToolTip createToolTip() {
        return Tooltips.createHtmlToolTip(this);
    }
}
