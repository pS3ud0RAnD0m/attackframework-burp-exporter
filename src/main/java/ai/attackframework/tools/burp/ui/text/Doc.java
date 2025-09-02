package ai.attackframework.tools.burp.ui.text;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * Small adapter to reduce boilerplate when wiring document change events to a {@link Runnable}.
 *
 * <p>All callbacks are forwarded as the same action; this is appropriate for UI cases where
 * insert/remove/changed should share identical behavior.</p>
 */
public final class Doc {

    private Doc() {}

    /**
     * Return a {@link DocumentListener} that invokes the given action on any document change.
     * Caller should ensure this runs on the EDT in Swing contexts.
     *
     * @param action action to invoke
     * @return a listener delegating all events to {@code action}
     */
    public static DocumentListener onChange(Runnable action) {
        return new DocumentListener() {
            private void run() { action.run(); }
            @Override public void insertUpdate(DocumentEvent e) { run(); }
            @Override public void removeUpdate(DocumentEvent e) { run(); }
            @Override public void changedUpdate(DocumentEvent e) { run(); }
        };
    }
}
