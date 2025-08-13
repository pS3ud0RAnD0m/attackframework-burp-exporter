package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.Logger;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Log view with level filter, pause autoscroll, clear/copy/save, search, and duplicate compaction.
 * Comments favor intent/design over narration.
 */
public class LogPanel extends JPanel implements Logger.LogListener {

    private final JTextPane logTextPane;
    private final StyledDocument doc;
    private final Style infoStyle;
    private final Style errorStyle;
    private final DateTimeFormatter timestampFormat;

    // Controls
    private final JComboBox<String> levelCombo;
    private final JCheckBox pauseAutoscroll;
    private final JTextField searchField;
    private final JButton searchPrevBtn;
    private final JButton searchNextBtn;
    private final JButton clearBtn;
    private final JButton copyBtn;
    private final JButton saveBtn;

    // Model and view state
    private final List<Entry> entries = new ArrayList<>();
    private int lastLineStart = 0;     // last rendered line offset
    private int lastLineLen   = 0;     // last rendered line length

    // Search state
    private List<int[]> matches = List.of(); // list of [start, end] on current doc text
    private int matchIndex = -1;

    // Level ordering (TRACE < DEBUG < INFO < WARN < ERROR)
    private enum L { TRACE, DEBUG, INFO, WARN, ERROR }
    private static L toLevel(String s) {
        try { return L.valueOf(s == null ? "INFO" : s.trim().toUpperCase(Locale.ROOT)); }
        catch (IllegalArgumentException ex) { return L.INFO; }
    }

    /** Simple event record; repeats tracks consecutive duplicates at ingest time. */
    private static final class Entry {
        final LocalDateTime ts;
        final L level;
        final String message;
        int repeats; // >= 1

        Entry(LocalDateTime ts, L level, String message) {
            this.ts = ts; this.level = level; this.message = message; this.repeats = 1;
        }
    }

    /** Builds the panel, toolbar, and styles. */
    public LogPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        // Editor
        logTextPane = new JTextPane();
        logTextPane.setEditable(false);
        logTextPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logTextPane.setBackground(UIManager.getColor("TextPane.background"));
        logTextPane.setForeground(UIManager.getColor("TextPane.foreground"));
        doc = logTextPane.getStyledDocument();

        timestampFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        infoStyle = doc.addStyle("INFO", null);
        StyleConstants.setForeground(infoStyle, UIManager.getColor("TextPane.foreground"));

        errorStyle = doc.addStyle("ERROR", null);
        StyleConstants.setForeground(errorStyle, UIManager.getColor("TextPane.foreground"));
        StyleConstants.setBold(errorStyle, true);

        // Toolbar
        JPanel toolbar = new JPanel(new MigLayout("insets 6 8 6 8, fillx, novisualpadding", "[][grow][][][][][]20[][][]", "[]"));
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")));

        levelCombo = new JComboBox<>(new String[]{"TRACE", "DEBUG", "INFO", "WARN", "ERROR"});
        levelCombo.setSelectedItem("DEBUG"); // default view filter
        levelCombo.setName("log.filter.level");

        pauseAutoscroll = new JCheckBox("Pause");
        pauseAutoscroll.setName("log.pause");

        searchField = new JTextField();
        searchField.setColumns(24);
        searchField.setName("log.search.field");

        searchPrevBtn = new JButton("Prev");
        searchPrevBtn.setName("log.search.prev");

        searchNextBtn = new JButton("Next");
        searchNextBtn.setName("log.search.next");

        clearBtn = new JButton("Clear");
        clearBtn.setName("log.clear");

        copyBtn = new JButton("Copy");
        copyBtn.setName("log.copy");

        saveBtn = new JButton("Save…");
        saveBtn.setName("log.save");

        toolbar.add(new JLabel("Min level:"));
        toolbar.add(levelCombo, "w 110!");
        toolbar.add(new JSeparator(), "h 12!, gapleft 8, gapright 8");
        toolbar.add(new JLabel("Find:"));
        toolbar.add(searchField, "growx");
        toolbar.add(searchPrevBtn, "gapleft 6");
        toolbar.add(searchNextBtn, "gapleft 4");
        toolbar.add(new JSeparator(), "h 12!, gapleft 12, gapright 8");
        toolbar.add(pauseAutoscroll);
        toolbar.add(clearBtn, "gapleft 8");
        toolbar.add(copyBtn, "gapleft 4");
        toolbar.add(saveBtn, "gapleft 4");

        add(toolbar, BorderLayout.NORTH);

        JScrollPane scrollPane = new JScrollPane(
                logTextPane,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
        );
        add(scrollPane, BorderLayout.CENTER);

        // Wiring
        levelCombo.addActionListener(e -> rebuildView());
        pauseAutoscroll.addActionListener(e -> {
            if (!pauseAutoscroll.isSelected()) {
                logTextPane.setCaretPosition(doc.getLength());
            }
        });

        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { computeMatchesAndJumpFirst(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { computeMatchesAndJumpFirst(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { computeMatchesAndJumpFirst(); }
        });
        searchPrevBtn.addActionListener(e -> jumpMatch(-1));
        searchNextBtn.addActionListener(e -> jumpMatch(+1));

        clearBtn.addActionListener(e -> {
            entries.clear();
            clearDoc();
            matches = List.of();
            matchIndex = -1;
        });

        copyBtn.addActionListener(e -> {
            try {
                String selected = logTextPane.getSelectedText();
                String all = selected != null && !selected.isEmpty()
                        ? selected
                        : doc.getText(0, doc.getLength());
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(all), null);
            } catch (Exception ex) {
                Logger.logError("Copy failed: " + ex.getMessage());
            }
        });

        saveBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Save Log");
            chooser.setSelectedFile(new File("attackframework-burp-exporter-log.txt"));
            int result = chooser.showSaveDialog(this);
            if (result != JFileChooser.APPROVE_OPTION) return;

            File out = chooser.getSelectedFile();
            try {
                String text = doc.getText(0, doc.getLength());
                FileUtil.writeStringCreateDirs(out.toPath(), text);
                Logger.logInfo("Log saved to " + out.getAbsolutePath());
            } catch (IOException | BadLocationException ex) {
                Logger.logError("Save failed: " + ex.getMessage());
            }
        });

        // Listener lifecycle: register now; unregister on removal.
        Logger.registerListener(this);
    }

    @Override
    public void removeNotify() {
        super.removeNotify();
        Logger.unregisterListener(this);
    }

    // ---- Logger.LogListener ----

    @Override
    public void onLog(String level, String message) {
        SwingUtilities.invokeLater(() -> ingest(level, message));
    }

    // ---- Ingest + rendering ----

    private void ingest(String levelStr, String message) {
        L lvl = toLevel(levelStr);
        LocalDateTime now = LocalDateTime.now();

        // Compact consecutive duplicates at ingest-time
        if (!entries.isEmpty()) {
            Entry last = entries.get(entries.size() - 1);
            if (last.level == lvl && safeEquals(last.message, message)) {
                last.repeats++;
                // If visible, update the last rendered line in place
                if (passesFilter(last.level)) {
                    replaceLastRenderedLine(formatLine(now, last.level, last.message, last.repeats),
                            last.level == L.ERROR ? errorStyle : infoStyle);
                    autoscrollIfNeeded();
                    computeMatchesAfterDocChange();
                }
                return;
            }
        }

        Entry e = new Entry(now, lvl, message);
        entries.add(e);
        if (passesFilter(e.level)) {
            appendLine(formatLine(e.ts, e.level, e.message, e.repeats),
                    e.level == L.ERROR ? errorStyle : infoStyle);
            autoscrollIfNeeded();
            computeMatchesAfterDocChange();
        }
    }

    private boolean passesFilter(L lvl) {
        L min = toLevel((String) levelCombo.getSelectedItem());
        return lvl.ordinal() >= min.ordinal();
    }

    /** Rebuilds the document from model with current filter and compaction. */
    private void rebuildView() {
        clearDoc();
        LocalDateTime ts = null;
        L lvl = null;
        String msg = null;
        int count = 0;

        for (Entry e : entries) {
            if (!passesFilter(e.level)) continue;

            if (lvl == e.level && safeEquals(msg, e.message)) {
                // continue compaction group (use latest timestamp)
                count += e.repeats;
                ts = e.ts;
            } else {
                // flush previous
                if (lvl != null) {
                    appendLine(formatLine(ts, lvl, msg, count), lvl == L.ERROR ? errorStyle : infoStyle);
                }
                // start new group
                ts = e.ts; lvl = e.level; msg = e.message; count = e.repeats;
            }
        }
        if (lvl != null) {
            appendLine(formatLine(ts, lvl, msg, count), lvl == L.ERROR ? errorStyle : infoStyle);
        }
        autoscrollIfNeeded();
        computeMatchesAfterDocChange();
    }

    private String formatLine(LocalDateTime ts, L lvl, String msg, int repeats) {
        String timestamp = "[" + timestampFormat.format(ts == null ? LocalDateTime.now() : ts) + "]";
        String base = String.format("%s [%s] %s", timestamp, lvl.name(), msg == null ? "" : msg);
        return repeats > 1 ? base + "  (x" + repeats + ")\n" : base + "\n";
    }

    private void appendLine(String line, Style style) {
        try {
            int start = doc.getLength();
            doc.insertString(start, line, style);
            lastLineStart = start;
            lastLineLen = line.length();
        } catch (BadLocationException e) {
            // Keep UI resilient; surface to logger
            Logger.logError("Append failed: " + e.getMessage());
        }
    }

    private void replaceLastRenderedLine(String line, Style style) {
        try {
            doc.remove(lastLineStart, lastLineLen);
            doc.insertString(lastLineStart, line, style);
            lastLineLen = line.length();
        } catch (BadLocationException e) {
            Logger.logError("Replace failed: " + e.getMessage());
        }
    }

    private void clearDoc() {
        try {
            doc.remove(0, doc.getLength());
            lastLineStart = 0;
            lastLineLen = 0;
        } catch (BadLocationException e) {
            Logger.logError("Clear failed: " + e.getMessage());
        }
    }

    private void autoscrollIfNeeded() {
        if (!pauseAutoscroll.isSelected()) {
            logTextPane.setCaretPosition(doc.getLength());
        }
    }

    // ---- Search ----

    private void computeMatchesAndJumpFirst() {
        computeMatchesAfterDocChange();
        if (!matches.isEmpty()) {
            matchIndex = 0;
            selectMatch(matchIndex);
        } else {
            matchIndex = -1;
            logTextPane.select(doc.getLength(), doc.getLength());
        }
    }

    private void computeMatchesAfterDocChange() {
        String q = searchField.getText();
        if (q == null || q.isEmpty()) {
            matches = List.of();
            return;
        }
        try {
            String hay = doc.getText(0, doc.getLength());
            String qLower = q.toLowerCase(Locale.ROOT);
            String hayLower = hay.toLowerCase(Locale.ROOT);

            List<int[]> found = new ArrayList<>();
            int idx = 0;
            while (true) {
                idx = hayLower.indexOf(qLower, idx);
                if (idx < 0) break;
                found.add(new int[]{idx, idx + q.length()});
                idx += Math.max(1, q.length());
            }
            matches = found;
        } catch (BadLocationException e) {
            matches = List.of();
        }
    }

    private void jumpMatch(int delta) {
        if (matches.isEmpty()) return;
        matchIndex = (matchIndex + delta) % matches.size();
        if (matchIndex < 0) matchIndex += matches.size();
        selectMatch(matchIndex);
    }

    private void selectMatch(int i) {
        if (i < 0 || i >= matches.size()) return;
        int[] m = matches.get(i);
        logTextPane.select(m[0], m[1]);
        logTextPane.requestFocusInWindow();
    }

    private static boolean safeEquals(String a, String b) {
        return (a == null) ? b == null : a.equals(b);
    }
}
