package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.Logger;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.AbstractAction;
import javax.swing.KeyStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.io.File;
import java.io.IOException;

/**
 * Log view with level filter, pause autoscroll, clear/copy/save, search (highlight all matches),
 * and duplicate compaction. Theme colors are taken from UIManager to match Burp’s LAF.
 */
public class LogPanel extends JPanel implements Logger.LogListener {

    // Editor + styles
    private final JTextPane logTextPane;
    private final StyledDocument doc;
    private final Style infoStyle;
    private final Style errorStyle;
    private final DateTimeFormatter timestampFormat;

    // Controls that affect behavior beyond constructor
    private final javax.swing.JComboBox<String> levelCombo;
    private final JCheckBox pauseAutoscroll;
    private final JTextField searchField;

    // Model and view state
    private final List<Entry> entries = new ArrayList<>();
    private int lastLineStart = 0;     // last rendered line offset
    private int lastLineLen   = 0;     // last rendered line length

    // Search state & highlighting (single theme-aware painter)
    private final Highlighter.HighlightPainter matchPainter;
    private final List<Object> matchTags = new ArrayList<>();
    private List<int[]> matches = List.of(); // [start, end] pairs
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

        // Theme-aware highlight color (align with Burp defaults)
        Color sel = UIManager.getColor("TextField.selectionBackground");
        if (sel == null) sel = UIManager.getColor("TextArea.selectionBackground");
        if (sel == null) sel = new Color(180, 200, 255); // fallback
        matchPainter = new DefaultHighlighter.DefaultHighlightPainter(sel);

        // Toolbar (compact; search group left-aligned tightly)
        JPanel toolbar = new JPanel(new MigLayout(
                "insets 6 8 6 8, fillx, novisualpadding, gapx 6",
                "", "[]"));
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")));

        levelCombo = new javax.swing.JComboBox<>(new String[]{"TRACE", "DEBUG", "INFO", "WARN", "ERROR"});
        levelCombo.setSelectedItem("DEBUG"); // default verbose
        levelCombo.setName("log.filter.level");

        pauseAutoscroll = new JCheckBox("Pause autoscroll");
        pauseAutoscroll.setName("log.pause");

        searchField = new JTextField();
        searchField.setColumns(28);
        searchField.setName("log.search.field");
        final JButton searchPrevBtn = new JButton("Prev");
        searchPrevBtn.setName("log.search.prev");
        final JButton searchNextBtn = new JButton("Next");
        searchNextBtn.setName("log.search.next");

        JButton clearBtn = new JButton("Clear");
        clearBtn.setName("log.clear");
        JButton copyBtn = new JButton("Copy");
        copyBtn.setName("log.copy");
        JButton saveBtn = new JButton("Save…");
        saveBtn.setName("log.save");

        // Build toolbar: level | | Find: [field] Prev Next | (spacer) | pause | clear copy save
        toolbar.add(new JLabel("Min level:"));
        toolbar.add(levelCombo, "w 110!");
        toolbar.add(new JSeparator(JSeparator.VERTICAL), "h 18!, gapx 8");

        // Search group left-aligned tightly
        toolbar.add(new JLabel("Find:"), "gapx 0");
        toolbar.add(searchField, "gapx 0");
        toolbar.add(searchPrevBtn, "gapx 4");
        toolbar.add(searchNextBtn, "gapx 4");

        toolbar.add(new JLabel(), "pushx, growx"); // spacer

        toolbar.add(new JSeparator(JSeparator.VERTICAL), "h 18!, gapx 8");
        toolbar.add(pauseAutoscroll);
        toolbar.add(clearBtn, "gapx 8");
        toolbar.add(copyBtn, "gapx 4");
        toolbar.add(saveBtn, "gapx 4");

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

        // Search: keep focus where the user put it; Enter in field => Next
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { computeMatchesAndJumpFirst(); }
            public void removeUpdate(DocumentEvent e) { computeMatchesAndJumpFirst(); }
            public void changedUpdate(DocumentEvent e) { computeMatchesAndJumpFirst(); }
        });
        // Reliable key binding for Enter = Next (works across LAFs)
        searchField.getInputMap(JTextField.WHEN_FOCUSED)
                .put(KeyStroke.getKeyStroke("ENTER"), "log.search.next");
        searchField.getActionMap().put("log.search.next", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { jumpMatch(+1); }
        });

        searchPrevBtn.addActionListener(e -> jumpMatch(-1));
        searchNextBtn.addActionListener(e -> jumpMatch(+1));

        clearBtn.addActionListener(e -> {
            entries.clear();
            clearDoc();
            clearSearchHighlights();
            matches = List.of();
            matchIndex = -1;
        });

        copyBtn.addActionListener(e -> {
            try {
                String selected = logTextPane.getSelectedText();
                String all = (selected != null && !selected.isEmpty())
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
            String ts = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").format(LocalDateTime.now());
            chooser.setSelectedFile(new File("attackframework-burp-exporter-" + ts + ".log"));
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
            Entry last = entries.getLast();
            if (last.level == lvl && Objects.equals(last.message, message)) {
                last.repeats++;
                if (passesFilter(last.level)) {
                    replaceLastRenderedLine(
                            formatLine(now, last.level, last.message, last.repeats),
                            last.level == L.ERROR ? errorStyle : infoStyle
                    );
                    autoscrollIfNeeded();
                    recomputeMatchesAfterDocChange();
                }
                return;
            }
        }

        Entry e = new Entry(now, lvl, message);
        entries.add(e);
        if (passesFilter(e.level)) {
            appendLine(
                    formatLine(e.ts, e.level, e.message, e.repeats),
                    e.level == L.ERROR ? errorStyle : infoStyle
            );
            autoscrollIfNeeded();
            recomputeMatchesAfterDocChange();
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

            if (lvl == e.level && Objects.equals(msg, e.message)) {
                count += e.repeats;
                ts = e.ts;
            } else {
                if (lvl != null) {
                    appendLine(formatLine(ts, lvl, msg, count), lvl == L.ERROR ? errorStyle : infoStyle);
                }
                ts = e.ts; lvl = e.level; msg = e.message; count = e.repeats;
            }
        }
        if (lvl != null) {
            appendLine(formatLine(ts, lvl, msg, count), lvl == L.ERROR ? errorStyle : infoStyle);
        }
        autoscrollIfNeeded();
        recomputeMatchesAfterDocChange();
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

    // ---- Search + highlight (single painter) ----

    private void computeMatchesAndJumpFirst() {
        recomputeMatchesAfterDocChange();
        if (!matches.isEmpty()) {
            matchIndex = 0;
            revealMatch(matchIndex);
        } else {
            matchIndex = -1;
        }
        // No focus stealing: let the user keep focus where they are (field or buttons)
    }

    private void recomputeMatchesAfterDocChange() {
        String q = searchField.getText();
        clearSearchHighlights();
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
                int end = idx + q.length();
                found.add(new int[]{idx, end});

                Object tag = logTextPane.getHighlighter().addHighlight(idx, end, matchPainter);
                matchTags.add(tag);

                idx = end;
            }
            matches = found;
        } catch (BadLocationException e) {
            matches = List.of();
        }
    }

    private void clearSearchHighlights() {
        Highlighter h = logTextPane.getHighlighter();
        for (Object tag : matchTags) {
            try { h.removeHighlight(tag); } catch (RuntimeException ignore) { }
        }
        matchTags.clear();
    }

    private void jumpMatch(int delta) {
        if (matches.isEmpty()) return;
        matchIndex = (matchIndex + delta) % matches.size();
        if (matchIndex < 0) matchIndex += matches.size();
        revealMatch(matchIndex);
        // Do not force focus anywhere; respect current focus (field or buttons)
    }

    private void revealMatch(int i) {
        if (i < 0 || i >= matches.size()) return;
        int[] m = matches.get(i);
        ensureVisible(m[0]);
    }

    private void ensureVisible(int offset) {
        try {
            Rectangle r = logTextPane.modelToView2D(offset).getBounds();
            logTextPane.scrollRectToVisible(r);
        } catch (BadLocationException ignore) {
        }
    }
}
