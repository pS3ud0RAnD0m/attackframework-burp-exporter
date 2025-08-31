package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.Logger;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
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
import javax.swing.text.Highlighter.HighlightPainter;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.AbstractAction;
import javax.swing.KeyStroke;
import javax.swing.JComponent;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.prefs.Preferences;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Log view with level filter, pause autoscroll, clear/copy/save, text filter (case/regex),
 * search (case/regex, highlight all, match count), and duplicate compaction.
 * Theme colors come from UIManager to align with Burp’s LAF. Minimal persistence via Preferences.
 */
public class LogPanel extends JPanel implements Logger.LogListener {

    @Serial
    private static final long serialVersionUID = 1L;

    // UIManager keys
    private static final String UI_TEXT_FOREGROUND = "TextPane.foreground";
    private static final String UI_TEXT_BACKGROUND = "TextPane.background";
    private static final String UI_SEL_BG_FIELD    = "TextField.selectionBackground";
    private static final String UI_SEL_BG_AREA     = "TextArea.selectionBackground";

    // MigLayout snippets
    private static final String MIG_TOOLBAR_INSETS = "insets 6 8 6 8, fillx, novisualpadding, gapx 6";
    private static final String MIG_SEP            = "h 18!, gapx 8";
    private static final String GAP0               = "gapx 0";
    private static final String GAP4               = "gapx 4";
    private static final String GAP6               = "gapx 6";
    private static final String GAP8               = "gapx 8";

    // Actions / defaults
    private static final String ACTION_SEARCH_NEXT = "log.search.next";
    private static final String DEFAULT_MIN_LEVEL  = "DEBUG";

    // Editor and styles
    private final JTextPane logTextPane;
    private final transient StyledDocument doc;
    private final transient Style infoStyle;
    private final transient Style errorStyle;
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Controls
    private final JComboBox<String> levelCombo;
    private final JCheckBox pauseAutoscroll;

    // Filter controls
    private final JTextField filterField;
    private final JCheckBox filterCaseToggle;
    private final JCheckBox filterRegexToggle;
    private final JLabel filterRegexIndicator = new JLabel();

    // Search controls
    private final JTextField searchField;
    private final JCheckBox searchCaseToggle;
    private final JCheckBox searchRegexToggle;
    private final JLabel searchRegexIndicator = new JLabel();
    private final JLabel searchCountLabel;

    // Model and view state
    private final List<Entry> entries = new ArrayList<>();
    private int lastLineStart = 0;
    private int lastLineLen   = 0;

    // Search state and highlighting
    private final transient HighlightPainter matchPainter;
    private final transient List<Object> matchTags = new ArrayList<>();
    private List<int[]> matches = List.of(); // [start, end] pairs
    private int matchIndex = -1;

    // Persistence
    private static final Preferences PREFS = Preferences.userRoot().node("ai.attackframework.tools.burp.ui.LogPanel");
    private static final String PREF_MIN_LEVEL     = "minLevel";
    private static final String PREF_PAUSE         = "pauseAutoscroll";
    private static final String PREF_LAST_SEARCH   = "lastSearch";
    private static final String PREF_FILTER_TEXT   = "filterText";
    private static final String PREF_FILTER_CASE   = "filterCase";
    private static final String PREF_FILTER_REGEX  = "filterRegex";

    // Memory cap
    private static final int MAX_MODEL_ENTRIES = 5000;

    // Levels (TRACE < DEBUG < INFO < WARN < ERROR)
    private enum L { TRACE, DEBUG, INFO, WARN, ERROR }
    private static L toLevel(String s) {
        try { return L.valueOf(s == null ? "INFO" : s.trim().toUpperCase(Locale.ROOT)); }
        catch (IllegalArgumentException ex) { return L.INFO; }
    }

    /** Minimal event; repeats tracks consecutive duplicates during ingestion. */
    private static final class Entry {
        final LocalDateTime ts;
        final L level;
        final String message;
        int repeats; // >= 1
        Entry(LocalDateTime ts, L level, String message) {
            this.ts = ts; this.level = level; this.message = message; this.repeats = 1;
        }
    }

    public LogPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        // Editor
        logTextPane = new JTextPane();
        logTextPane.setEditable(false);
        logTextPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logTextPane.setBackground(UIManager.getColor(UI_TEXT_BACKGROUND));
        logTextPane.setForeground(UIManager.getColor(UI_TEXT_FOREGROUND));
        doc = logTextPane.getStyledDocument();

        infoStyle = doc.addStyle("INFO", null);
        StyleConstants.setForeground(infoStyle, UIManager.getColor(UI_TEXT_FOREGROUND));

        errorStyle = doc.addStyle("ERROR", null);
        StyleConstants.setForeground(errorStyle, UIManager.getColor(UI_TEXT_FOREGROUND));
        StyleConstants.setBold(errorStyle, true);

        // Highlight color from LAF
        Color sel = UIManager.getColor(UI_SEL_BG_FIELD);
        if (sel == null) sel = UIManager.getColor(UI_SEL_BG_AREA);
        if (sel == null) sel = new Color(180, 200, 255);
        matchPainter = new DefaultHighlighter.DefaultHighlightPainter(sel);

        // Toolbar
        JPanel toolbar = new JPanel(new MigLayout(MIG_TOOLBAR_INSETS, "", "[]"));
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")));

        levelCombo = new JComboBox<>(new String[]{"TRACE", DEFAULT_MIN_LEVEL, "INFO", "WARN", "ERROR"});
        levelCombo.setName("log.filter.level");
        levelCombo.setSelectedItem(PREFS.get(PREF_MIN_LEVEL, DEFAULT_MIN_LEVEL));

        pauseAutoscroll = new JCheckBox("Pause autoscroll");
        pauseAutoscroll.setName("log.pause");
        pauseAutoscroll.setSelected(PREFS.getBoolean(PREF_PAUSE, false));

        // Filter group (restore persisted)
        filterField = new JTextField(PREFS.get(PREF_FILTER_TEXT, ""));
        filterField.setColumns(18);
        filterField.setName("log.filter.text");
        filterCaseToggle = new JCheckBox("Aa");
        filterCaseToggle.setToolTipText("Case-sensitive filter");
        filterCaseToggle.setName("log.filter.case");
        filterCaseToggle.setSelected(PREFS.getBoolean(PREF_FILTER_CASE, false));
        filterRegexToggle = new JCheckBox(".*");
        filterRegexToggle.setToolTipText("Regex filter");
        filterRegexToggle.setName("log.filter.regex");
        filterRegexToggle.setSelected(PREFS.getBoolean(PREF_FILTER_REGEX, false));

        // Search group (restore last search text only)
        searchField = new JTextField(PREFS.get(PREF_LAST_SEARCH, ""));
        searchField.setColumns(18);
        searchField.setName("log.search.field");
        searchCaseToggle = new JCheckBox("Aa");
        searchCaseToggle.setToolTipText("Case-sensitive search");
        searchCaseToggle.setName("log.search.case");
        searchRegexToggle = new JCheckBox(".*");
        searchRegexToggle.setToolTipText("Regex search");
        searchRegexToggle.setName("log.search.regex");
        JButton searchPrevBtn = new JButton("Prev");
        searchPrevBtn.setName("log.search.prev");
        JButton searchNextBtn = new JButton("Next");
        searchNextBtn.setName(ACTION_SEARCH_NEXT);
        searchCountLabel = new JLabel("0/0");
        searchCountLabel.setName("log.search.count");

        JButton clearBtn = new JButton("Clear");
        clearBtn.setName("log.clear");
        JButton copyBtn = new JButton("Copy");
        copyBtn.setName("log.copy");
        JButton saveBtn = new JButton("Save…");
        saveBtn.setName("log.save");

        // Build toolbar
        toolbar.add(new JLabel("Min level:"));
        toolbar.add(levelCombo, "w 110!");
        toolbar.add(new JSeparator(SwingConstants.VERTICAL), MIG_SEP);

        toolbar.add(new JLabel("Filter:"), GAP0);
        toolbar.add(filterField, GAP0);
        toolbar.add(filterCaseToggle, GAP4);
        toolbar.add(filterRegexToggle, GAP4);
        toolbar.add(filterRegexIndicator, GAP6);

        toolbar.add(new JSeparator(SwingConstants.VERTICAL), MIG_SEP);

        toolbar.add(new JLabel("Find:"), GAP0);
        toolbar.add(searchField, GAP0);
        toolbar.add(searchCaseToggle, GAP4);
        toolbar.add(searchRegexToggle, GAP4);
        toolbar.add(searchRegexIndicator, GAP6);
        toolbar.add(searchPrevBtn, GAP4);
        toolbar.add(searchNextBtn, GAP4);
        toolbar.add(searchCountLabel, GAP6);

        toolbar.add(new JLabel(), "pushx, growx");

        toolbar.add(new JSeparator(SwingConstants.VERTICAL), MIG_SEP);
        toolbar.add(pauseAutoscroll);
        toolbar.add(clearBtn, GAP8);
        toolbar.add(copyBtn, GAP4);
        toolbar.add(saveBtn, GAP4);

        add(toolbar, BorderLayout.NORTH);

        JScrollPane scrollPane = new JScrollPane(
                logTextPane,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        );
        add(scrollPane, BorderLayout.CENTER);

        // Context menu
        JPopupMenu menu = buildContextMenu();
        logTextPane.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e)  { maybeShow(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShow(e); }
            private void maybeShow(MouseEvent e) {
                if (e.isPopupTrigger()) menu.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        // Wiring
        levelCombo.addActionListener(e -> {
            PREFS.put(PREF_MIN_LEVEL, Objects.toString(levelCombo.getSelectedItem(), DEFAULT_MIN_LEVEL));
            rebuildView();
        });

        pauseAutoscroll.addActionListener(e -> {
            PREFS.putBoolean(PREF_PAUSE, pauseAutoscroll.isSelected());
            if (!pauseAutoscroll.isSelected()) {
                logTextPane.setCaretPosition(doc.getLength());
            }
        });

        DocumentListener filterChange = onDocChange(() -> {
            saveFilterPrefsAndRebuild();
            updateFilterRegexFeedback();
        });
        filterField.getDocument().addDocumentListener(filterChange);
        filterCaseToggle.addActionListener(e -> saveFilterPrefsAndRebuild());
        filterRegexToggle.addActionListener(e -> { saveFilterPrefsAndRebuild(); updateFilterRegexFeedback(); });

        DocumentListener searchChange = onDocChange(() -> {
            PREFS.put(PREF_LAST_SEARCH, searchField.getText());
            updateSearchRegexFeedback();
            computeMatchesAndJumpFirst();
        });
        searchField.getDocument().addDocumentListener(searchChange);
        searchField.getInputMap(JComponent.WHEN_FOCUSED)
                .put(KeyStroke.getKeyStroke("ENTER"), ACTION_SEARCH_NEXT);
        searchField.getActionMap().put(ACTION_SEARCH_NEXT, new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { jumpMatch(+1); }
        });
        searchCaseToggle.addActionListener(e -> { updateSearchRegexFeedback(); computeMatchesAndJumpFirst(); });
        searchRegexToggle.addActionListener(e -> { updateSearchRegexFeedback(); computeMatchesAndJumpFirst(); });

        searchPrevBtn.addActionListener(e -> jumpMatch(-1));
        searchNextBtn.addActionListener(e -> jumpMatch(+1));

        clearBtn.addActionListener(e -> {
            entries.clear();
            clearDoc();
            clearSearchHighlights();
            matches = List.of();
            matchIndex = -1;
            updateMatchCount();
        });

        copyBtn.addActionListener(e -> copySelectionOrAll());
        saveBtn.addActionListener(e -> saveVisible());

        Logger.registerListener(this);

        // Initial state after restoring persisted values
        rebuildView();
        updateFilterRegexFeedback();
        updateSearchRegexFeedback();
        computeMatchesAndJumpFirst();
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

    // ---- Ingest and rendering ----

    private void ingest(String levelStr, String message) {
        L lvl = toLevel(levelStr);
        LocalDateTime now = LocalDateTime.now();

        // Compact consecutive duplicates during ingestion
        if (!entries.isEmpty()) {
            Entry last = entries.getLast();
            if (last.level == lvl && Objects.equals(last.message, message)) {
                last.repeats++;
                if (visible(last.level, last.message)) {
                    replaceLastRenderedLine(
                            formatLine(now, last.level, last.message, last.repeats),
                            last.level == L.ERROR ? errorStyle : infoStyle
                    );
                    autoscrollIfNeeded();
                    recomputeMatchesAfterDocChange();
                }
                trimIfNeeded();
                return;
            }
        }

        Entry e = new Entry(now, lvl, message);
        entries.add(e);
        if (visible(e.level, e.message)) {
            appendLine(
                    formatLine(e.ts, e.level, e.message, e.repeats),
                    e.level == L.ERROR ? errorStyle : infoStyle
            );
            autoscrollIfNeeded();
            recomputeMatchesAfterDocChange();
        }
        trimIfNeeded();
    }

    private boolean visible(L lvl, String message) {
        return passesLevel(lvl) && passesTextFilter(message);
    }

    private boolean passesLevel(L lvl) {
        L min = toLevel((String) levelCombo.getSelectedItem());
        return lvl.ordinal() >= min.ordinal();
    }

    private boolean passesTextFilter(String msg) {
        String f = filterField.getText();
        if (f == null || f.isEmpty()) return true;

        try {
            if (filterRegexToggle.isSelected()) {
                int flags = filterCaseToggle.isSelected() ? 0 : (Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
                return Pattern.compile(f, flags).matcher(msg == null ? "" : msg).find();
            } else {
                String m = msg == null ? "" : msg;
                return filterCaseToggle.isSelected()
                        ? m.contains(f)
                        : m.toLowerCase(Locale.ROOT).contains(f.toLowerCase(Locale.ROOT));
            }
        } catch (PatternSyntaxException ex) {
            // Invalid regexes => treat as non-match.
            return false;
        }
    }

    /** Rebuilds the document from a model with current level/text filters. */
    private void rebuildView() {
        clearDoc();

        LocalDateTime aggTs = null;
        L aggLvl = null;
        String aggMsg = null;
        int aggCount = 0;

        for (Entry e : entries) {
            if (!visible(e.level, e.message)) {
                continue;
            }

            boolean same = (aggLvl == e.level && Objects.equals(aggMsg, e.message));
            if (same) {
                aggCount += e.repeats;
                aggTs = e.ts;
            } else {
                if (aggLvl != null) {
                    appendAggregated(aggTs, aggLvl, aggMsg, aggCount);
                }
                aggTs = e.ts;
                aggLvl = e.level;
                aggMsg = e.message;
                aggCount = e.repeats;
            }
        }
        if (aggLvl != null) {
            appendAggregated(aggTs, aggLvl, aggMsg, aggCount);
        }

        autoscrollIfNeeded();
        recomputeMatchesAfterDocChange();
    }

    private void appendAggregated(LocalDateTime ts, L lvl, String msg, int count) {
        appendLine(formatLine(ts, lvl, msg, count), lvl == L.ERROR ? errorStyle : infoStyle);
    }

    private void trimIfNeeded() {
        if (entries.size() > MAX_MODEL_ENTRIES) {
            int remove = entries.size() - MAX_MODEL_ENTRIES;
            entries.subList(0, remove).clear();
            rebuildView();
        }
    }

    private String formatLine(LocalDateTime ts, L lvl, String msg, int repeats) {
        String timestamp = "[" + TIMESTAMP_FORMAT.format(ts == null ? LocalDateTime.now() : ts) + "]";
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

    // ---- Search and highlight ----

    private void computeMatchesAndJumpFirst() {
        recomputeMatchesAfterDocChange();
        if (!matches.isEmpty()) {
            matchIndex = 0;
            revealMatch(matchIndex);
        } else {
            matchIndex = -1;
        }
        updateMatchCount();
    }

    private void recomputeMatchesAfterDocChange() {
        String q = searchField.getText();
        clearSearchHighlights();
        if (q == null || q.isEmpty()) {
            matches = List.of();
            updateMatchCount();
            return;
        }

        try {
            String hay = doc.getText(0, doc.getLength());
            List<int[]> found = searchRegexToggle.isSelected()
                    ? findRegexMatches(hay, q, searchCaseToggle.isSelected())
                    : findSubstringMatches(hay, q, searchCaseToggle.isSelected());

            applyHighlights(found);
            matches = found;
        } catch (BadLocationException | PatternSyntaxException e) {
            matches = List.of();
        }

        updateMatchCount();
    }

    private List<int[]> findRegexMatches(String hay, String q, boolean caseSensitive) {
        Pattern p = compilePatternWithFlags(q, computeRegexFlags(caseSensitive, true));
        Matcher m = p.matcher(hay);
        List<int[]> found = new ArrayList<>();
        while (m.find()) {
            found.add(new int[]{m.start(), m.end()});
        }
        return found;
    }

    private List<int[]> findSubstringMatches(String hay, String q, boolean caseSensitive) {
        String hay2 = caseSensitive ? hay : hay.toLowerCase(Locale.ROOT);
        String q2 = caseSensitive ? q : q.toLowerCase(Locale.ROOT);
        List<int[]> found = new ArrayList<>();
        int idx = 0;
        while (true) {
            idx = hay2.indexOf(q2, idx);
            if (idx < 0) break;
            int end = idx + q2.length();
            found.add(new int[]{idx, end});
            idx = end;
        }
        return found;
    }

    private void applyHighlights(List<int[]> ranges) throws BadLocationException {
        Highlighter h = logTextPane.getHighlighter();
        for (int[] r : ranges) {
            Object tag = h.addHighlight(r[0], r[1], matchPainter);
            matchTags.add(tag);
        }
    }

    private static int computeRegexFlags(boolean caseSensitive, boolean multiline) {
        int flags = 0;
        if (!caseSensitive) flags |= (Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
        if (multiline)      flags |= Pattern.MULTILINE;
        return flags;
    }

    @SuppressWarnings("MagicConstant")
    private static Pattern compilePatternWithFlags(String pattern, int flags) {
        return Pattern.compile(pattern, flags);
    }

    private void clearSearchHighlights() {
        Highlighter h = logTextPane.getHighlighter();
        for (Object tag : matchTags) {
            try {
                h.removeHighlight(tag);
            } catch (RuntimeException ignore) {
                // Best-effort: tag may be stale if the document changed aggressively.
            }
        }
        matchTags.clear();
    }

    private void jumpMatch(int delta) {
        if (matches.isEmpty()) return;
        matchIndex = (matchIndex + delta) % matches.size();
        if (matchIndex < 0) matchIndex += matches.size();
        revealMatch(matchIndex);
        updateMatchCount();
    }

    private void revealMatch(int i) {
        if (i < 0 || i >= matches.size()) return;
        int[] m = matches.get(i);
        ensureVisible(m[0]);
    }

    // Guard against null from modelToView2D when the component isn't realized yet (e.g., headless tests).
    private void ensureVisible(int offset) {
        try {
            var r2d = logTextPane.modelToView2D(offset);
            if (r2d == null) {
                return; // not displayable yet; skip scrolling
            }
            java.awt.Rectangle r = r2d.getBounds();
            logTextPane.scrollRectToVisible(r);
        } catch (javax.swing.text.BadLocationException ignore) {
            // Invalid offsets are harmless; visibility is best-effort.
        }
    }

    private void updateMatchCount() {
        int total = matches == null ? 0 : matches.size();
        int idx1 = (matchIndex >= 0 && total > 0) ? (matchIndex + 1) : 0;
        searchCountLabel.setText(idx1 + "/" + total);
    }

    // ---- Copy/Save helpers ----

    private void copySelectionOrAll() {
        String sel = logTextPane.getSelectedText();
        if (sel != null && !sel.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sel), null);
            return;
        }
        copyAll();
    }

    private void copySelection() {
        String sel = logTextPane.getSelectedText();
        if (sel == null || sel.isEmpty()) return;
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sel), null);
    }

    private void copyCurrentLine() {
        try {
            int caret = logTextPane.getCaretPosition();
            String text = doc.getText(0, doc.getLength());
            int start = text.lastIndexOf('\n', Math.max(0, caret - 1)) + 1;
            int end = text.indexOf('\n', caret);
            if (end < 0) end = text.length();
            String line = text.substring(start, end);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(line), null);
        } catch (BadLocationException ignore) {
            // Selection helpers are best-effort; ignore bad caret offsets.
        }
    }

    private void copyAll() {
        try {
            String all = doc.getText(0, doc.getLength());
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(all), null);
        } catch (BadLocationException ignore) {
            // Best-effort: if the document length changed mid-read, skip copy.
        }
    }

    private void saveVisible() {
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
        } catch (IOException | BadLocationException ex) {
            Logger.logError("Save failed: " + ex.getMessage());
        }
    }

    // chooser-free helper for tests

    @SuppressWarnings("unused")
    void saveVisibleTo(Path out) throws IOException {
        try {
            String text = doc.getText(0, doc.getLength());
            FileUtil.writeStringCreateDirs(out, text);
        } catch (BadLocationException e) {
            throw new IOException("Failed reading document", e);
        }
    }

    // ---- Persistence helpers ----

    private void saveFilterPrefsAndRebuild() {
        PREFS.put(PREF_FILTER_TEXT, filterField.getText());
        PREFS.putBoolean(PREF_FILTER_CASE, filterCaseToggle.isSelected());
        PREFS.putBoolean(PREF_FILTER_REGEX, filterRegexToggle.isSelected());
        rebuildView();
    }

    // ---- UI helpers ----

    private JPopupMenu buildContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copySel = new JMenuItem("Copy selection");
        JMenuItem copyLine = new JMenuItem("Copy current line");
        JMenuItem copyAll = new JMenuItem("Copy all");
        JMenuItem saveVisible = new JMenuItem("Save visible…");
        copySel.addActionListener(e -> copySelection());
        copyLine.addActionListener(e -> copyCurrentLine());
        copyAll.addActionListener(e -> copyAll());
        saveVisible.addActionListener(e -> saveVisible());
        menu.add(copySel);
        menu.add(copyLine);
        menu.add(copyAll);
        menu.addSeparator();
        menu.add(saveVisible);
        return menu;
    }

    // ---- Regex validity indicators ----

    private void updateSearchRegexFeedback() {
        updateRegexIndicator(
                searchField,
                searchRegexToggle,
                searchCaseToggle,
                true,
                searchRegexIndicator
        );
    }

    private void updateFilterRegexFeedback() {
        updateRegexIndicator(
                filterField,
                filterRegexToggle,
                filterCaseToggle,
                false,
                filterRegexIndicator
        );
    }

    private void updateRegexIndicator(
            JTextField field,
            JCheckBox regexToggle,
            JCheckBox caseToggle,
            boolean includeMultilineFlag,
            JLabel indicator
    ) {
        String txt = field.getText();

        Color base = UIManager.getColor("TextField.background");
        if (base == null) base = logTextPane.getBackground();
        field.setBackground(base);

        if (!regexToggle.isSelected() || txt == null || txt.isBlank()) {
            indicator.setVisible(false);
            indicator.setText("");
            indicator.setToolTipText(null);
            return;
        }

        try {
            compilePatternWithFlags(txt, computeRegexFlags(caseToggle.isSelected(), includeMultilineFlag));
            indicator.setForeground(new Color(0, 153, 0));
            indicator.setText("✓");
            indicator.setToolTipText("Valid regex");
            indicator.setVisible(true);
        } catch (PatternSyntaxException ex) {
            indicator.setForeground(new Color(200, 0, 0));
            indicator.setText("✖");
            indicator.setToolTipText(ex.getDescription());
            indicator.setVisible(true);
        }
    }

    // ---- Small helper to avoid duplicated DocumentListener bodies ----
    private static DocumentListener onDocChange(Runnable action) {
        return new DocumentListener() {
            private void on() { action.run(); }
            @Override public void insertUpdate(DocumentEvent e) { on(); }
            @Override public void removeUpdate(DocumentEvent e) { on(); }
            @Override public void changedUpdate(DocumentEvent e) { on(); }
        };
    }
}
