package ai.attackframework.tools.burp.ui.text;

import ai.attackframework.tools.burp.utils.Regex;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.event.ActionListener;
import java.awt.event.ItemListener;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Binds a text field and toggle(s) to a small indicator label that shows a
 * ✓ (valid) or ✖ (invalid) when regex mode is enabled.
 *
 * <h3>Behavior</h3>
 * <ul>
 *   <li>Indicator is hidden when regex mode is off or the field is blank.</li>
 *   <li>Indicator shows ✓ (green) for a valid pattern; ✖ (red) otherwise.</li>
 *   <li>Indicator width is fixed to the max of both glyphs to avoid jitter.</li>
 * </ul>
 */
public final class RegexIndicatorBinder {

    private RegexIndicatorBinder() {
        // utility
    }

    /**
     * Wire listeners and keep the indicator in sync with the current state.
     *
     * @param field             source text field
     * @param regexToggle       checkbox controlling regex mode
     * @param caseToggleOrNull  optional checkbox controlling case sensitivity (may be {@code null})
     * @param multiline         whether multiline anchors should be applied
     * @param indicator         target label for ✓ / ✖
     * @return handle that detaches listeners when closed
     */
    public static AutoCloseable bind(
            JTextField field,
            JCheckBox regexToggle,
            JCheckBox caseToggleOrNull,
            boolean multiline,
            JLabel indicator
    ) {
        Objects.requireNonNull(field, "field");
        Objects.requireNonNull(regexToggle, "regexToggle");
        Objects.requireNonNull(indicator, "indicator");

        final ListenerGroup group = new ListenerGroup(field, regexToggle, caseToggleOrNull, multiline, indicator);
        group.install();
        group.refresh(); // initial paint
        return group::uninstall;
    }

    /* ----------------------------- internals ----------------------------- */

    private static final class ListenerGroup {
        private static final Color GREEN = new Color(0, 153, 0);
        private static final Color RED = new Color(200, 0, 0);

        private final JTextField field;
        private final JCheckBox regexToggle;
        private final JCheckBox caseToggleOrNull;
        private final boolean multiline;
        private final JLabel indicator;

        private final AtomicBoolean installed = new AtomicBoolean(false);

        private final DocumentListener docListener = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { refresh(); }
            @Override public void removeUpdate(DocumentEvent e) { refresh(); }
            @Override public void changedUpdate(DocumentEvent e) { refresh(); }
        };

        private final ItemListener itemListener = e -> refresh();
        private final ActionListener actionListener = e -> refresh();

        ListenerGroup(JTextField field, JCheckBox regexToggle, JCheckBox caseToggleOrNull, boolean multiline, JLabel indicator) {
            this.field = field;
            this.regexToggle = regexToggle;
            this.caseToggleOrNull = caseToggleOrNull;
            this.multiline = multiline;
            this.indicator = indicator;
        }

        void install() {
            if (!installed.compareAndSet(false, true)) return;

            field.getDocument().addDocumentListener(docListener);
            regexToggle.addItemListener(itemListener);
            regexToggle.addActionListener(actionListener);
            if (caseToggleOrNull != null) {
                caseToggleOrNull.addItemListener(itemListener);
                caseToggleOrNull.addActionListener(actionListener);
            }

            // Ensure consistent font/size with a safety check for glyph coverage.
            syncIndicatorFont();
            fixIndicatorWidth();
            indicator.setHorizontalAlignment(SwingConstants.CENTER);
            indicator.setOpaque(false);
        }

        void uninstall() {
            if (!installed.compareAndSet(true, false)) return;

            field.getDocument().removeDocumentListener(docListener);
            regexToggle.removeItemListener(itemListener);
            regexToggle.removeActionListener(actionListener);
            if (caseToggleOrNull != null) {
                caseToggleOrNull.removeItemListener(itemListener);
                caseToggleOrNull.removeActionListener(actionListener);
            }
        }

        void refresh() {
            // keep font/width in sync in case LAF or font changes dynamically
            syncIndicatorFont();
            fixIndicatorWidth();

            final boolean regex = regexToggle.isSelected();
            final String txt = field.getText();
            final boolean show = regex && txt != null && !txt.isBlank();

            if (!show) {
                indicator.setText("");
                indicator.setToolTipText(null);
                indicator.setVisible(false);
                revalidateAndRepaint();
                return;
            }

            final boolean caseSensitive = caseToggleOrNull != null && caseToggleOrNull.isSelected();
            final boolean valid = Regex.isValid(txt, caseSensitive, multiline);
            if (valid) {
                good(indicator);
            } else {
                bad(indicator);
            }
            indicator.setVisible(true);
            revalidateAndRepaint();
        }

        private void syncIndicatorFont() {
            final Font fieldFont = field.getFont();
            final Font current = indicator.getFont();

            if (fieldFont != null && canRenderSymbols(fieldFont)) {
                if (!fieldFont.equals(current)) {
                    indicator.setFont(fieldFont);
                }
            } else if (current == null || !canRenderSymbols(current)) {
                final int size = deriveFontSize(fieldFont, current);
                indicator.setFont(new Font("Dialog", Font.PLAIN, size));
            }
        }

        private static int deriveFontSize(Font fieldFont, Font current) {
            if (fieldFont != null) return fieldFont.getSize();
            if (current != null) return current.getSize();
            return 12;
        }

        private static boolean canRenderSymbols(Font f) {
            return f.canDisplay('✓') && f.canDisplay('✖');
        }

        private void fixIndicatorWidth() {
            final FontMetrics fm = indicator.getFontMetrics(indicator.getFont());
            final int w = Math.max(fm.stringWidth("✓"), fm.stringWidth("✖")) + fm.charWidth(' ');
            final int h = fm.getHeight(); // always a non-zero height
            final Dimension d = new Dimension(w, h);

            final Dimension pref = indicator.getPreferredSize();
            if (pref == null || pref.width != d.width || pref.height != d.height) {
                indicator.setMinimumSize(d);
                indicator.setPreferredSize(d);
            }
        }

        private static void good(JLabel label) {
            label.setForeground(GREEN);
            label.setText("✓");
            label.setToolTipText("Valid regex");
        }

        private static void bad(JLabel label) {
            label.setForeground(RED);
            label.setText("✖");
            label.setToolTipText("Invalid regex");
        }

        private void revalidateAndRepaint() {
            final Container parent = indicator.getParent();
            if (parent != null) {
                parent.revalidate();
                parent.repaint();
            }
            indicator.revalidate();
            indicator.repaint();
        }
    }
}
