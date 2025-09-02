package ai.attackframework.tools.burp.ui.text;

import ai.attackframework.tools.burp.utils.Regex;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Color;
import java.awt.event.ActionListener;
import java.awt.event.ItemListener;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Binds a text field (plus toggles) to a ✓/✖ indicator that reflects regex validity.
 *
 * <p>Responds to:</p>
 * <ul>
 *   <li>Text changes (via a {@link DocumentListener}).</li>
 *   <li>Toggle changes (both {@link java.awt.event.ActionEvent ActionEvent} and
 *       {@link java.awt.event.ItemEvent ItemEvent}) so programmatic
 *       {@code setSelected(...)} and user clicks both refresh the indicator.</li>
 * </ul>
 *
 * <h3>Usage</h3>
 * <pre>{@code
 * AutoCloseable handle = RegexIndicatorBinder.bind(field, regexToggle, caseToggle, false, indicator);
 * // later (optional)
 * handle.close();
 * }</pre>
 *
 * <h3>Notes</h3>
 * <ul>
 *   <li>All updates are expected to occur on the EDT (typical Swing usage).</li>
 *   <li>The binder hides the indicator when regex mode is off or the field is blank.</li>
 *   <li>Compilation is delegated to {@link Regex}; any runtime failure (e.g.,
 *       {@link java.util.regex.PatternSyntaxException}) yields a red ✖ and a tooltip.</li>
 * </ul>
 */
public final class RegexIndicatorBinder {

    private RegexIndicatorBinder() {}

    /**
     * Bind field/toggles to an indicator label and return a handle that can unbind listeners.
     *
     * @param field            text input (required)
     * @param regexToggle      toggles regex mode on/off (required)
     * @param caseToggleOrNull case-sensitivity toggle (optional; may be {@code null})
     * @param multiline        whether MULTILINE should be applied while validating the pattern
     * @param indicator        target label (required)
     * @return a handle whose {@link AutoCloseable#close()} removes listeners
     * @throws NullPointerException if any required argument is {@code null}
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

    /**
     * Internal listener bundle. Keeps registration/unregistration in one place so we can
     * cleanly detach without leaking listeners if a panel is rebuilt or disposed.
     */
    private static final class ListenerGroup {
        private final JTextField field;
        private final JCheckBox regexToggle;
        private final JCheckBox caseToggle; // may be null
        private final boolean multiline;
        private final JLabel indicator;

        // Listeners
        private final DocumentListener docListener;
        private final ActionListener regexActionListener;
        private final ItemListener    regexItemListener;
        private final ActionListener caseActionListener;
        private final ItemListener    caseItemListener;

        private final AtomicBoolean disposed = new AtomicBoolean(false);

        ListenerGroup(JTextField field,
                      JCheckBox regexToggle,
                      JCheckBox caseToggle,
                      boolean multiline,
                      JLabel indicator) {
            this.field = field;
            this.regexToggle = regexToggle;
            this.caseToggle = caseToggle;
            this.multiline = multiline;
            this.indicator = indicator;

            this.docListener = new DocumentListener() {
                @Override public void insertUpdate(DocumentEvent e) { refresh(); }
                @Override public void removeUpdate(DocumentEvent e) { refresh(); }
                @Override public void changedUpdate(DocumentEvent e) { refresh(); }
            };

            // Action + Item: handle both user clicks and programmatic setSelected(...)
            this.regexActionListener = e -> refresh();
            this.regexItemListener   = e -> refresh();

            this.caseActionListener  = e -> refresh();
            this.caseItemListener    = e -> refresh();
        }

        void install() {
            field.getDocument().addDocumentListener(docListener);

            regexToggle.addActionListener(regexActionListener);
            regexToggle.addItemListener(regexItemListener);

            if (caseToggle != null) {
                caseToggle.addActionListener(caseActionListener);
                caseToggle.addItemListener(caseItemListener);
            }
        }

        void uninstall() {
            if (disposed.getAndSet(true)) return;

            field.getDocument().removeDocumentListener(docListener);

            regexToggle.removeActionListener(regexActionListener);
            regexToggle.removeItemListener(regexItemListener);

            if (caseToggle != null) {
                caseToggle.removeActionListener(caseActionListener);
                caseToggle.removeItemListener(caseItemListener);
            }
        }

        /**
         * Recompute indicator state. Hidden when regex is off or input is blank;
         * green ✓ if compilation succeeds; red ✖ with a tooltip if it fails.
         */
        void refresh() {
            final String txt = field.getText();

            if (!regexToggle.isSelected() || txt == null || txt.isBlank()) {
                indicator.setVisible(false);
                indicator.setText("");
                indicator.setToolTipText(null);
                return;
            }

            final boolean caseSensitive = caseToggle != null && caseToggle.isSelected();
            try {
                Regex.compile(txt, caseSensitive, multiline); // validate only
                ok(indicator);
            } catch (RuntimeException ex) {
                bad(indicator, ex.getMessage());
            }
        }

        private static void ok(JLabel label) {
            label.setForeground(new Color(0, 153, 0));
            label.setText("✓");
            label.setToolTipText("Valid regex");
            label.setVisible(true);
        }

        private static void bad(JLabel label, String tooltip) {
            label.setForeground(new Color(200, 0, 0));
            label.setText("✖");
            label.setToolTipText(tooltip != null && !tooltip.isBlank() ? tooltip : "Invalid regex");
            label.setVisible(true);
        }
    }
}
