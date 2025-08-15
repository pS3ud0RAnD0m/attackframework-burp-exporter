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
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;

import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import javax.swing.text.Document;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import java.util.function.Supplier;

public class LogPanelTestHarness {

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

    public static LogPanel newPanelOnEdt() {
        return onEdt(LogPanel::new);
    }

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
                switch (c) {
                    case JMenu jMenu -> java.util.Collections.addAll(q, jMenu.getMenuComponents());
                    case JMenuBar jMenuBar -> {
                        for (MenuElement el : jMenuBar.getSubElements()) {
                            if (el.getComponent() != null) q.add(el.getComponent());
                        }
                    }
                    case Container container -> java.util.Collections.addAll(q, container.getComponents());
                    default -> {
                    }
                }
            }
            return null;
        });
    }

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

    /** First (and only) JTextPane inside LogPanel. */
    public static JTextPane textPane(LogPanel root) {
        Component c = findBy(root, comp -> comp instanceof JTextPane);
        if (c instanceof JTextPane pane) return pane;
        throw new IllegalStateException("No JTextPane found in LogPanel");
    }

    // ---------- Convenience actions ----------

    public static void setText(JTextField f, String s) {
        onEdt(() -> f.setText(s));
    }

    public static void click(AbstractButton b) {
        onEdt(() -> b.doClick());
    }

    public static boolean waitFor(Supplier<Boolean> cond, long timeoutMs) {
        long until = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < until) {
            if (Boolean.TRUE.equals(cond.get())) return true;
            onEdt(() -> {});
            java.util.concurrent.locks.LockSupport.parkNanos(15_000_000L);
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

    // ---------- Optional reflection helpers for context menu ----------

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

    public static void triggerSearchNextViaEnter(LogPanel p) {
        onEdt(() -> {
            JTextField sf = field(p, "log.search.field");
            Action a = sf.getActionMap().get("log.search.next");
            if (a == null) throw new IllegalStateException("No action for 'log.search.next'");
            a.actionPerformed(new ActionEvent(sf, ActionEvent.ACTION_PERFORMED, "ENTER"));
        });
    }

    // ---------- Test-state helpers ----------

    /** Reset persisted UI state so each test starts clean. */
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
     * Ensure the panel and its text pane have a non-zero size and are laid out,
     * so modelToView2D(...) returns a real rectangle in headless tests.
     */
    public static void realize(LogPanel p) {
        onEdt(() -> {
            if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                p.setSize(900, 700);
            }
            p.doLayout();
            JTextPane tp = textPane(p);
            if (tp.getWidth() <= 0 || tp.getHeight() <= 0) {
                tp.setSize(p.getWidth(), p.getHeight() - 40);
            }
            tp.doLayout();
        });
    }

    /**
     * Toggle pause via the checkbox (fires listeners) and align caret policy,
     * so headless behavior matches the real UI.
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
