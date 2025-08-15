package ai.attackframework.tools.burp.ui;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Shared utilities for LogPanel headless tests.
 * - Creates components on the EDT
 * - Finds child components by name/tooltip/text
 * - Simple polling waitFor
 * - Text getters/setters and button clicks on the EDT
 * - Optional access to LogPanel's context menu via reflection (if needed by tests)
 */
public class LogPanelTestHarness {

    /** Public no-arg constructor so tests can extend this harness freely. */
    public LogPanelTestHarness() {}

    // ---------- EDT helpers ----------

    public static void onEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
            return;
        }
        try {
            SwingUtilities.invokeAndWait(r);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(ie);
        } catch (InvocationTargetException ite) {
            throw asRuntime(ite.getTargetException());
        }
    }

    public static <T> T onEdt(Callable<T> c) {
        if (SwingUtilities.isEventDispatchThread()) {
            try {
                return c.call();
            } catch (Exception e) {
                throw asRuntime(e);
            }
        }
        final Object[] box = new Object[1];
        onEdt(() -> {
            try {
                box[0] = c.call();
            } catch (Exception e) {
                throw asRuntime(e);
            }
        });
        @SuppressWarnings("unchecked")
        T result = (T) box[0];
        return result;
    }

    private static RuntimeException asRuntime(Throwable t) {
        return (t instanceof RuntimeException) ? (RuntimeException) t : new RuntimeException(t);
    }

    // ---------- Panel factory ----------

    /** Create a new LogPanel on the EDT. */
    public static LogPanel newPanelOnEdt() {
        return onEdt(LogPanel::new);
    }

    /** Alias some tests may call. */
    public static LogPanel newPanel() {
        return newPanelOnEdt();
    }

    // ---------- Generic component lookup ----------

    public static Component findBy(LogPanel root, Predicate<Component> p) {
        return onEdt(() -> {
            Queue<Component> q = new ArrayDeque<>();
            q.add(root);
            while (!q.isEmpty()) {
                Component c = q.remove();
                if (p.test(c)) return c;
                if (c instanceof JMenu) {
                    for (Component child : ((JMenu) c).getMenuComponents()) q.add(child);
                } else if (c instanceof JMenuBar) {
                    for (MenuElement el : ((JMenuBar) c).getSubElements()) {
                        if (el.getComponent() != null) q.add(el.getComponent());
                    }
                } else if (c instanceof Container) {
                    for (Component child : ((Container) c).getComponents()) q.add(child);
                }
            }
            return null;
        });
    }

    public static Component findByNameOrTooltipOrText(LogPanel root, String key) {
        return findBy(root, c -> {
            String nm = (c instanceof JComponent) ? ((JComponent) c).getName() : null;
            String tip = (c instanceof JComponent) ? ((JComponent) c).getToolTipText() : null;
            String txt = (c instanceof AbstractButton) ? ((AbstractButton) c).getText()
                    : (c instanceof JLabel) ? ((JLabel) c).getText()
                    : null;
            return Objects.equals(nm, key) || Objects.equals(tip, key) || Objects.equals(txt, key);
        });
    }

    public static JTextField field(LogPanel root, String nameOrTooltipOrText) {
        Component c = findByNameOrTooltipOrText(root, nameOrTooltipOrText);
        if (!(c instanceof JTextField)) throw new IllegalStateException("No JTextField: " + nameOrTooltipOrText);
        return (JTextField) c;
    }

    public static JButton button(LogPanel root, String nameOrTooltipOrText) {
        Component c = findByNameOrTooltipOrText(root, nameOrTooltipOrText);
        if (!(c instanceof JButton)) throw new IllegalStateException("No JButton: " + nameOrTooltipOrText);
        return (JButton) c;
    }

    public static JCheckBox check(LogPanel root, String nameOrTooltipOrText) {
        Component c = findByNameOrTooltipOrText(root, nameOrTooltipOrText);
        if (!(c instanceof JCheckBox)) throw new IllegalStateException("No JCheckBox: " + nameOrTooltipOrText);
        return (JCheckBox) c;
    }

    @SuppressWarnings("rawtypes")
    public static JComboBox combo(LogPanel root, String nameOrTooltipOrText) {
        Component c = findByNameOrTooltipOrText(root, nameOrTooltipOrText);
        if (!(c instanceof JComboBox)) throw new IllegalStateException("No JComboBox: " + nameOrTooltipOrText);
        return (JComboBox) c;
    }

    public static JLabel labelMatching(LogPanel root, Pattern pattern) {
        Component c = findBy(root, comp -> comp instanceof JLabel && pattern.matcher(((JLabel) comp).getText()).matches());
        if (c == null) throw new IllegalStateException("No JLabel matching: " + pattern);
        return (JLabel) c;
    }

    /** The match-count label in LogPanel shows as "n/m". We locate it by that pattern. */
    public static String searchCountText(LogPanel root) {
        JLabel lbl = (JLabel) findBy(root, comp -> comp instanceof JLabel &&
                ((JLabel) comp).getText() != null &&
                ((JLabel) comp).getText().matches("\\d+/\\d+"));
        return onEdt(() -> lbl != null ? ((JLabel) lbl).getText() : "0/0");
    }

    /** First (and only) JTextPane inside LogPanel, used to read visible text. */
    public static JTextPane textPane(LogPanel root) {
        Component c = findBy(root, comp -> comp instanceof JTextPane);
        if (!(c instanceof JTextPane)) throw new IllegalStateException("No JTextPane found in LogPanel");
        return (JTextPane) c;
    }

    // ---------- Convenience actions ----------

    public static void setText(JTextField field, String value) {
        onEdt(() -> field.setText(value));
    }

    public static void click(AbstractButton b) {
        onEdt(b::doClick);
    }

    public static boolean waitFor(Supplier<Boolean> cond, long timeoutMs) {
        long until = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < until) {
            if (Boolean.TRUE.equals(cond.get())) return true;
            // pump the EDT
            onEdt(() -> {});
            try { Thread.sleep(15); } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    public static String allText(LogPanel p) {
        return onEdt(() -> {
            JTextPane pane = textPane(p);
            Document d = pane.getDocument();
            try {
                return d.getText(0, d.getLength());
            } catch (BadLocationException e) {
                throw new RuntimeException(e);
            }
        });
    }

    /** Invoke LogPanel's private buildContextMenu via reflection (for context-menu tests). */
    public static JPopupMenu buildContextMenuViaReflection(LogPanel p) {
        return onEdt(() -> {
            try {
                Method m = LogPanel.class.getDeclaredMethod("buildContextMenu");
                m.setAccessible(true);
                Object o = m.invoke(p);
                if (!(o instanceof JPopupMenu)) throw new IllegalStateException("Unexpected menu: " + o);
                return (JPopupMenu) o;
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                throw asRuntime(e);
            }
        });
    }

    /** Simulate pressing Enter in the search field by invoking the bound action. */
    public static void triggerSearchNextViaEnter(LogPanel p) {
        onEdt(() -> {
            JTextField sf = field(p, "log.search.field");
            Action a = sf.getActionMap().get("log.search.next");
            if (a == null) throw new IllegalStateException("No action for 'log.search.next'");
            a.actionPerformed(new ActionEvent(sf, ActionEvent.ACTION_PERFORMED, "ENTER"));
        });
    }
}
