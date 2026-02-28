package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.event.ActionEvent;

import javax.swing.AbstractButton;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.MenuElement;
import javax.swing.JPopupMenu;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import javax.swing.text.Document;

import java.util.ArrayDeque;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import java.util.function.Supplier;

import static ai.attackframework.tools.burp.testutils.Reflect.call;

/**
 * Test-only harness for working with LogPanel in headless mode.
 *
 * <p>Intent:</p>
 * - Provide safe helpers for executing actions on the EDT.
 * - Offer resilient component discovery by name, tooltip, or text.
 * - Expose convenient actions and state management primitives for tests.
 *
 * <p>Notes:</p>
 * - All Swing mutations run on the EDT via onEdt(Runnable) / onEdt(Callable).
 * - The harness avoids reflection except where the production class deliberately
 *   hides behavior; when needed, reflection goes through the shared test utility.
 */
public class LogPanelTestHarness {

    /** Public no-arg constructor so tests can instantiate freely. */
    public LogPanelTestHarness() { /* intentional no-op */ }

    // ---------- EDT helpers ----------

    /**
     * Runs the given runnable on the EDT, blocking until completion.
     * Any exception is rethrown as a RuntimeException.
     */
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
        } catch (Exception ite) {
            throw asRuntime(ite.getCause() == null ? ite : ite.getCause());
        }
    }

    /**
     * Calls the given callable on the EDT and returns its result.
     * Any checked exception is rethrown as a RuntimeException.
     */
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

    /** Creates a new LogPanel on the EDT. */
    public static LogPanel newPanelOnEdt() {
        return onEdt(LogPanel::new);
    }

    /** Alias to emphasize tests should construct on the EDT. */
    public static LogPanel newPanel() {
        return newPanelOnEdt();
    }

    // ---------- Generic component lookup ----------

    /**
     * Breadth-first search for a component that matches the supplied predicate.
     * The search traverses standard Swing containers and menu structures.
     */
    public static Component findBy(LogPanel root, Predicate<Component> p) {
        return onEdt(() -> {
            Queue<Component> q = new ArrayDeque<>();
            q.add(root);
            while (!q.isEmpty()) {
                Component c = q.remove();
                if (p.test(c)) return c;
                switch (c) {
                    case JMenu jMenu -> java.util.Collections.addAll(q, jMenu.getMenuComponents());
                    case JMenuBar jMenuBar -> {
                        for (MenuElement el : jMenuBar.getSubElements()) {
                            if (el.getComponent() != null) q.add(el.getComponent());
                        }
                    }
                    case Container container -> java.util.Collections.addAll(q, container.getComponents());
                    default -> { /* ignore */ }
                }
            }
            return null;
        });
    }

    /**
     * Finds a component by matching any of: getName(), getToolTipText(),
     * or, for buttons/labels, getText().
     */
    public static Component findByNameOrTooltipOrText(LogPanel root, String key) {
        return findBy(root, c -> {
            String nm = null, tip = null, txt = null;
            if (c instanceof JComponent jc) {
                nm = jc.getName();
                tip = jc.getToolTipText();
            }
            if (c instanceof AbstractButton ab) {
                txt = ab.getText();
            } else if (c instanceof JLabel lbl) {
                txt = lbl.getText();
            }
            return Objects.equals(nm, key) || Objects.equals(tip, key) || Objects.equals(txt, key);
        });
    }

    // ---------- Named finders ----------

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

    /** Match-counter label text like "n/m". */
    public static String searchCountText(LogPanel root) {
        JLabel lbl = (JLabel) findBy(root, comp -> comp instanceof JLabel l &&
                l.getText() != null &&
                l.getText().matches("\\d+/\\d+"));
        return onEdt(() -> lbl != null ? lbl.getText() : "0/0");
    }

    /** First (and only) text area (log content) inside the panel. */
    public static JTextArea textPane(LogPanel root) {
        Component c = findBy(root, JTextArea.class::isInstance);
        if (c instanceof JTextArea area) return area;
        throw new IllegalStateException("No JTextArea found in LogPanel");
    }

    // ---------- Convenience actions ----------

    /** Sets text on a field on the EDT. */
    public static void setText(JTextField f, String s) {
        onEdt(() -> f.setText(s));
    }

    /** Clicks a button/checkbox on the EDT. */
    public static void click(AbstractButton b) {
        final Runnable r = b::doClick;  // explicit target type avoids overload ambiguity
        onEdt(r);
    }

    /**
     * Waits until the condition becomes true or the timeout elapses.
     * Pumps the EDT and parks briefly between checks.
     */
    public static boolean waitFor(Supplier<Boolean> cond, long timeoutMs) {
        long until = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < until) {
            if (Boolean.TRUE.equals(cond.get())) return true;
            onEdt(() -> { /* pump */ });
            java.util.concurrent.locks.LockSupport.parkNanos(15_000_000L);
        }
        return false;
    }

    /** Returns all text currently displayed in the panel’s text pane. */
    public static String allText(LogPanel p) {
        return onEdt(() -> {
            JTextArea pane = textPane(p);
            Document d = pane.getDocument();
            try {
                return d.getText(0, d.getLength());
            } catch (BadLocationException e) {
                throw new RuntimeException(e);
            }
        });
    }

    // ---------- Optional reflection-backed helpers for context menu ----------

    /**
     * Invokes the panel’s internal context-menu builder via the shared Reflection utility.
     * Allows tests to assert menu structure without widening production visibility.
     */
    public static JPopupMenu buildContextMenuViaReflection(LogPanel p) {
        return onEdt(() -> {
            Object o = call(p, "buildContextMenu");
            if (!(o instanceof JPopupMenu menu)) {
                throw new IllegalStateException("Unexpected menu: " + o);
            }
            return menu;
        });
    }

    /**
     * Fires the “search next” action bound to Enter in the search field.
     * Uses the action map key rather than synthesizing a key event.
     */
    public static void triggerSearchNextViaEnter(LogPanel p) {
        onEdt(() -> {
            JTextField sf = field(p, "log.search.field");
            Action a = sf.getActionMap().get("log.search.next");
            if (a == null) throw new IllegalStateException("No action for 'log.search.next'");
            a.actionPerformed(new ActionEvent(sf, ActionEvent.ACTION_PERFORMED, "ENTER"));
        });
    }

    // ---------- Test-state helpers ----------

    /** Resets persisted UI state so each test starts from a clean baseline. */
    public static void resetPanelState(LogPanel p) {
        @SuppressWarnings("unchecked")
        JComboBox<String> level = (JComboBox<String>) combo(p, "log.filter.level");
        onEdt(() -> level.setSelectedItem("INFO"));

        JCheckBox fCase = check(p, "log.filter.case");
        JCheckBox fRegex = check(p, "log.filter.regex");
        if (fCase.isSelected()) click(fCase);
        if (fRegex.isSelected()) click(fRegex);
        setText(field(p, "log.filter.text"), "");

        JCheckBox sCase = check(p, "log.search.case");
        JCheckBox sRegex = check(p, "log.search.regex");
        if (sCase.isSelected()) click(sCase);
        if (sRegex.isSelected()) click(sRegex);
        setText(field(p, "log.search.field"), "");
    }

    /**
     * Ensures the panel and its text pane have a non-zero size and are laid out,
     * so geometry-dependent APIs (for example, modelToView2D) return real rectangles.
     */
    public static void realize(LogPanel p) {
        onEdt(() -> {
            if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                p.setSize(900, 700);
            }
            p.doLayout();
            JTextArea tp = textPane(p);
            if (tp.getWidth() <= 0 || tp.getHeight() <= 0) {
                tp.setSize(p.getWidth(), p.getHeight() - 40);
            }
            tp.doLayout();
        });
    }

    /**
     * Toggles pause via the checkbox (firing listeners) and aligns the caret update policy,
     * so headless behavior matches the interactive UI.
     */
    public static void setPaused(LogPanel p, boolean paused) {
        JCheckBox pause = check(p, "log.pause");
        if (pause.isSelected() != paused) {
            click(pause);
        }
        onEdt(() -> {
            var caret = textPane(p).getCaret();
            if (caret instanceof DefaultCaret dc) {
                dc.setUpdatePolicy(paused ? DefaultCaret.NEVER_UPDATE : DefaultCaret.ALWAYS_UPDATE);
            }
        });
    }
}
