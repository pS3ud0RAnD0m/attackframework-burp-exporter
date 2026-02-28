package ai.attackframework.tools.burp.ui;

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
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.prefs.Preferences;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentListener;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter.HighlightPainter;

import net.miginfocom.swing.MigLayout;

import ai.attackframework.tools.burp.ui.log.LogRenderer;
import ai.attackframework.tools.burp.ui.log.LogStore;
import ai.attackframework.tools.burp.ui.text.IndentedWrappedTextAreaUI;
import ai.attackframework.tools.burp.ui.primitives.AutoSizingTextField;
import ai.attackframework.tools.burp.ui.primitives.ScrollPanes;
import ai.attackframework.tools.burp.ui.primitives.TextFieldUndo;
import ai.attackframework.tools.burp.ui.text.Doc;
import ai.attackframework.tools.burp.ui.text.HighlighterManager;
import ai.attackframework.tools.burp.ui.text.RegexIndicatorBinder;
import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.text.TextQuery;
import ai.attackframework.tools.burp.utils.text.TextSearchEngine;

/**
 * Log view with level filter, pause autoscroll, clear/copy/save, text filter (case/regex),
 * search (case/regex, highlight all, match count), and duplicate compaction.
 *
 * <p><strong>Design:</strong> Coordinates a {@link LogStore} (model) with a {@link LogRenderer} (view).
 * Keeps regex compilation and flag rules centralized via {@link ai.attackframework.tools.burp.utils.Regex}.</p>
 *
 * <p><strong>Threading:</strong> All UI mutations occur on the EDT. Logger callbacks are marshaled with
 * {@code invokeLater} to preserve ordering and avoid contention with highlight recomputation.</p>
 */
public class LogPanel extends JPanel implements Logger.ReplayableLogListener {

    @Serial
    private static final long serialVersionUID = 1L;

    // Toolbar layout snippets for consistency across rebuilds.
    private static final String MIG_TOOLBAR_INSETS = "insets 6 8 6 8, fillx, novisualpadding, gapx 6";
    private static final String MIG_SEP            = "h 18!, gapx 8";
    private static final String GAP0               = "gapx 0";
    private static final String GAP4               = "gapx 4";
    private static final String GAP6               = "gapx 6";
    private static final String GAP8               = "gapx 8";

    // Actions / defaults
    private static final String ACTION_SEARCH_NEXT = "log.search.next";
    private static final String DEFAULT_MIN_LEVEL  = "INFO";
    private static final int MAX_MODEL_ENTRIES     = 5000;

    // Editor and renderer (JTextArea for reliable line wrap; no horizontal scroll)
    private final JTextArea logTextPane;
    private final transient LogRenderer renderer;

    // Controls
    private final JComboBox<String> levelCombo;
    private final JCheckBox pauseAutoscroll;

    // Filter controls
    private final AutoSizingTextField filterField;
    private final JCheckBox filterCaseToggle;
    private final JCheckBox filterRegexToggle;

    // Search controls
    private final AutoSizingTextField searchField;
    private final JCheckBox searchCaseToggle;
    private final JCheckBox searchRegexToggle;
    private final JLabel searchCountLabel;

    // Search state and highlighting
    private final transient HighlighterManager highlighterManager;
    private List<int[]> matches = List.of(); // [start, end]
    private int matchIndex = -1;

    // Persistence
    private static final Preferences PREFS = Preferences.userRoot().node("ai.attackframework.tools.burp.ui.LogPanel");
    private static final String PREF_MIN_LEVEL     = "minLevel";
    private static final String PREF_PAUSE         = "pauseAutoscroll";
    private static final String PREF_LAST_SEARCH   = "lastSearch";
    private static final String PREF_FILTER_TEXT   = "filterText";
    private static final String PREF_FILTER_CASE   = "filterCase";
    private static final String PREF_FILTER_REGEX  = "filterRegex";

    // Indicator bindings (kept so removeNotify can unbind explicitly)
    private final transient AutoCloseable searchIndicatorBinding;
    private final transient AutoCloseable filterIndicatorBinding;

    // Model
    private final transient LogStore store;

    /** Constructs and wires the UI (EDT). */
    public LogPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        // Editor + renderer (JTextArea for reliable line wrap; no horizontal scroll bar; continuation indent on wrap)
        logTextPane = new JTextArea();
        logTextPane.setLineWrap(true);
        logTextPane.setWrapStyleWord(true);
        logTextPane.setUI(new IndentedWrappedTextAreaUI());
        logTextPane.setEditable(false);
        logTextPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logTextPane.setBackground(UIManager.getColor("TextArea.background"));
        logTextPane.setForeground(UIManager.getColor("TextArea.foreground"));
        renderer = new LogRenderer(logTextPane);

        // Highlight painter uses LAF color to integrate visually with theme.
        Color sel = UIManager.getColor("TextField.selectionBackground");
        if (sel == null) sel = UIManager.getColor("TextArea.selectionBackground");
        if (sel == null) sel = new Color(180, 200, 255);
        HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(sel);
        highlighterManager = new HighlighterManager(logTextPane, painter);

        // Toolbar
        JPanel toolbar = new JPanel(new MigLayout(MIG_TOOLBAR_INSETS, "", "[]"));
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")));

        levelCombo = new JComboBox<>(new String[]{"TRACE", "DEBUG", "INFO", "WARN", "ERROR"});
        levelCombo.setName("log.filter.level");
        levelCombo.setSelectedItem(PREFS.get(PREF_MIN_LEVEL, DEFAULT_MIN_LEVEL));

        pauseAutoscroll = new JCheckBox("Pause autoscroll");
        pauseAutoscroll.setName("log.pause");
        pauseAutoscroll.setSelected(PREFS.getBoolean(PREF_PAUSE, false));

        // Filter group (restore persisted)
        filterField = new AutoSizingTextField(PREFS.get(PREF_FILTER_TEXT, ""));
        filterField.setName("log.filter.text");
        filterCaseToggle = new JCheckBox("Aa");
        filterCaseToggle.setName("log.filter.case");
        filterCaseToggle.setSelected(PREFS.getBoolean(PREF_FILTER_CASE, false));
        filterRegexToggle = new JCheckBox(".*");
        filterRegexToggle.setName("log.filter.regex");
        final JLabel filterRegexIndicator = new JLabel();
        filterRegexIndicator.setName("log.filter.regex.indicator");

        // Search group (restore last search text only)
        searchField = new AutoSizingTextField(PREFS.get(PREF_LAST_SEARCH, ""));
        searchField.setName("log.search.field");
        searchCaseToggle = new JCheckBox("Aa");
        searchCaseToggle.setName("log.search.case");
        searchRegexToggle = new JCheckBox(".*");
        searchRegexToggle.setName("log.search.regex");
        JButton searchPrevBtn = new JButton("Prev");
        searchPrevBtn.setName("log.search.prev");
        JButton searchNextBtn = new JButton("Next");
        searchNextBtn.setName(ACTION_SEARCH_NEXT);
        searchCountLabel = new JLabel("0/0");
        searchCountLabel.setName("log.search.count");
        final JLabel searchRegexIndicator = new JLabel();
        searchRegexIndicator.setName("log.search.regex.indicator");

        JButton clearBtn = new JButton("Clear");
        clearBtn.setName("log.clear");
        JButton copyBtn = new JButton("Copy");
        copyBtn.setName("log.copy");
        JButton saveBtn = new JButton("Save…");
        saveBtn.setName("log.save");

        assignToolTips(
                searchPrevBtn,
                searchNextBtn,
                clearBtn,
                copyBtn,
                saveBtn
        );

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

        add(ScrollPanes.wrapNoHorizontalScroll(logTextPane), BorderLayout.CENTER);

        // Model created before listeners capture it; filter supplied via visible().
        store = new LogStore(MAX_MODEL_ENTRIES, this::visible);

        // Context menu (right-click on the log area)
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
            if (!pauseAutoscroll.isSelected()) renderer.autoscrollIfNeeded(false);
        });

        DocumentListener filterChange = Doc.onChange(() -> {
            PREFS.put(PREF_FILTER_TEXT, filterField.getText());
            rebuildView();
        });
        filterField.getDocument().addDocumentListener(filterChange);
        filterCaseToggle.addActionListener(e -> {
            PREFS.putBoolean(PREF_FILTER_CASE, filterCaseToggle.isSelected());
            rebuildView();
        });
        filterRegexToggle.addActionListener(e -> {
            PREFS.putBoolean(PREF_FILTER_REGEX, filterRegexToggle.isSelected());
            rebuildView();
        });

        DocumentListener searchChange = Doc.onChange(() -> {
            PREFS.put(PREF_LAST_SEARCH, searchField.getText());
            computeMatchesAndJumpFirst();
        });
        searchField.getDocument().addDocumentListener(searchChange);
        searchField.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke("ENTER"), ACTION_SEARCH_NEXT
        );
        searchField.getActionMap().put(ACTION_SEARCH_NEXT, new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { jumpMatch(+1); }
        });

        searchPrevBtn.addActionListener(e -> jumpMatch(-1));
        searchNextBtn.addActionListener(e -> jumpMatch(+1));

        clearBtn.addActionListener(e -> {
            Logger.internalDebug("LogPanel: clear requested");
            store.clear();
            renderer.clear();
            clearSearchHighlights();
            matches = List.of();
            matchIndex = -1;
            updateMatchCount();
            Logger.internalTrace("LogPanel: cleared, matches reset");
        });

        copyBtn.addActionListener(e -> copySelectionOrAll());
        saveBtn.addActionListener(e -> saveVisible());

        // Regex indicators (✓/✖). Binder enforces fixed width and glyph-safe font.
        searchIndicatorBinding = RegexIndicatorBinder.bind(
                searchField, searchRegexToggle, searchCaseToggle, true, searchRegexIndicator
        );
        filterIndicatorBinding = RegexIndicatorBinder.bind(
                filterField, filterRegexToggle, filterCaseToggle, false, filterRegexIndicator
        );

        TextFieldUndo.install(filterField);
        TextFieldUndo.install(searchField);

        rebuildView();
        computeMatchesAndJumpFirst();
    }

    /**
     * Registers with Logger when this panel is added to the display hierarchy.
     * Burp may remove our tab content when another top-level tab is selected and re-add when
     * the user switches back; we only receive log messages while registered, so we register
     * here and unregister in removeNotify. Logger replays recent messages to newly registered
     * listeners so the Log tab shows full history after a tab switch.
     */
    @Override
    public void addNotify() {
        super.addNotify();
        Logger.registerListener(this);
    }

    /**
     * Assigns tooltips for all toolbar controls in one place.
     * <p>
     * @param searchPrevBtn jump-to-previous button
     * @param searchNextBtn jump-to-next button
     * @param clearBtn      clear action button
     * @param copyBtn       copy action button
     * @param saveBtn       save action button
     */
    private void assignToolTips(
            JButton searchPrevBtn,
            JButton searchNextBtn,
            JButton clearBtn,
            JButton copyBtn,
            JButton saveBtn
    ) {
        levelCombo.setToolTipText("Minimum level to display");
        pauseAutoscroll.setToolTipText("Stop auto-scrolling when new entries arrive");

        filterField.setToolTipText("Filter by string or regex");
        filterCaseToggle.setToolTipText("Case-sensitive filter");
        filterRegexToggle.setToolTipText("Regex filter");

        searchField.setToolTipText("Find string or regex");
        searchCaseToggle.setToolTipText("Case-sensitive search");
        searchRegexToggle.setToolTipText("Regex search");

        searchPrevBtn.setToolTipText("Jump to previous match");
        searchNextBtn.setToolTipText("Jump to next match");

        clearBtn.setToolTipText("Clear log pane");
        copyBtn.setToolTipText("Copy log to clipboard");
        saveBtn.setToolTipText("Save log to file");
    }

    /**
     * Lifecycle hook: unregisters from Logger (so we stop receiving while not in the hierarchy)
     * and closes regex bindings when removed. Re-registration happens in addNotify when shown again.
     */
    @Override
    public void removeNotify() {
        super.removeNotify();
        Logger.unregisterListener(this);
        try { if (filterIndicatorBinding != null) filterIndicatorBinding.close(); }
        catch (Exception ex) { Logger.internalDebug("regex filter binder close skipped: " + ex); }
        try { if (searchIndicatorBinding != null) searchIndicatorBinding.close(); }
        catch (Exception ex) { Logger.internalDebug("regex search binder close skipped: " + ex); }
    }

    // ---- Logger.LogListener ----

    /**
     * Logger callback; invoked on the EDT by Logger so ingestion runs on the UI thread.
     *
     * @param level   level string from Logger
     * @param message log message (nullable)
     */
    @Override
    public void onLog(String level, String message) {
        ingest(level, message);
    }

    // ---- Ingest and rendering ----

    /**
     * Ingests a log event, rendering incrementally when visible.
     * <p>
     * @param levelStr level string (parsed via {@link LogStore.Level#fromString(String)})
     * @param message  log message (nullable)
     */
    private void ingest(String levelStr, String message) {
        LogStore.Level lvl = LogStore.Level.fromString(levelStr);
        Logger.internalTrace("LogPanel ingest -> level=" + lvl + " msg=" + (message == null ? "" : message));
        LocalDateTime now = LocalDateTime.now();

        LogStore.Decision d = store.ingest(lvl, message, now);
        switch (d.kind()) {
            case APPEND -> {
                String line = renderer.formatLine(d.entry().ts, d.entry().level, d.entry().message, d.entry().repeats());
                renderer.append(line, d.entry().level);
                Logger.internalTrace("LogPanel render=APPEND");
                renderer.autoscrollIfNeeded(pauseAutoscroll.isSelected());
                recomputeMatchesAfterDocChange();
            }
            case REPLACE -> {
                String line = renderer.formatLine(d.entry().ts, d.entry().level, d.entry().message, d.entry().repeats());
                renderer.replaceLast(line, d.entry().level);
                Logger.internalTrace("LogPanel render=REPLACE");
                renderer.autoscrollIfNeeded(pauseAutoscroll.isSelected());
                recomputeMatchesAfterDocChange();
            }
            default -> Logger.internalTrace("LogPanel render=NONE (filtered)");
        }
        if (store.trimIfNeeded()) {
            Logger.internalTrace("LogPanel cap reached -> rebuild");
            rebuildView();
        }
    }

    /**
     * Applies current filters to determine whether a log should render.
     * <p>
     * @param lvl     level to evaluate
     * @param message log message
     * @return {@code true} when the entry passes level and text filters
     */
    private boolean visible(LogStore.Level lvl, String message) {
        return passesLevel(lvl) && passesTextFilter(message);
    }

    /**
     * Checks whether a level meets or exceeds the selected minimum.
     * <p>
     * @param lvl level to evaluate
     * @return {@code true} when the level is visible
     */
    private boolean passesLevel(LogStore.Level lvl) {
        LogStore.Level min = LogStore.Level.fromString((String) levelCombo.getSelectedItem());
        return lvl.ordinal() >= min.ordinal();
    }

    /**
     * Text filter (regex or substring). Invalid regex results in WARN and non-match.
     * <p>
     * Regex flag rules (case/UNICODE) are centralized; substring matching lowers both
     * sides when case-insensitive to avoid locale pitfalls.
     * <p>
     * @param msg message to test
     * @return {@code true} when the message passes the text filter
     */
    private boolean passesTextFilter(String msg) {
        String f = filterField.getText();
        if (f == null || f.isEmpty()) return true;
        try {
            if (filterRegexToggle.isSelected()) {
                int flags = filterCaseToggle.isSelected()
                        ? 0
                        : (java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.UNICODE_CASE);
                return java.util.regex.Pattern.compile(f, flags)
                        .matcher(msg == null ? "" : msg)
                        .find();
            } else {
                String m = msg == null ? "" : msg;
                return filterCaseToggle.isSelected()
                        ? m.contains(f)
                        : m.toLowerCase(Locale.ROOT).contains(f.toLowerCase(Locale.ROOT));
            }
        } catch (RuntimeException ex) {
            Logger.internalWarn("LogPanel invalid regex: " + ex.getMessage());
            return false;
        }
    }

    /**
     * Full rebuild from the store using the current filter.
     */
    private void rebuildView() {
        store.setFilter(this::visible);
        renderer.clear();
        int rendered = 0;
        for (LogStore.Aggregate a : store.buildVisibleAggregated()) {
            String line = renderer.formatLine(a.ts(), a.level(), a.message(), a.count());
            renderer.append(line, a.level());
            rendered++;
        }
        renderer.autoscrollIfNeeded(pauseAutoscroll.isSelected());
        recomputeMatchesAfterDocChange();
        Logger.internalTrace("LogPanel rebuild done, lines=" + rendered);
    }

    // ---- Search / highlight ----

    /**
     * Recomputes search matches and jumps to the first result when present.
     */
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

    /**
     * Recomputes search highlights after the document changes.
     */
    private void recomputeMatchesAfterDocChange() {
        clearSearchHighlights();

        final String q = searchField.getText();
        if (q == null || q.isEmpty()) {
            matches = List.of();
            updateMatchCount();
            return;
        }

        try {
            final String hay = logTextPane.getDocument().getText(0, logTextPane.getDocument().getLength());
            final TextQuery tq = new TextQuery(
                    q, searchCaseToggle.isSelected(), searchRegexToggle.isSelected(), true
            );
            matches = TextSearchEngine.findAll(hay, tq);
            highlighterManager.apply(matches);
            Logger.internalTrace(
                    "LogPanel highlight recompute, matches=" + (matches == null ? 0 : matches.size())
            );
        } catch (Exception ex) {
            matches = List.of();
            Logger.internalDebug("LogPanel highlight recompute failed: " + ex);
        }
        updateMatchCount();
    }

    /**
     * Clears all applied search highlights.
     */
    private void clearSearchHighlights() { highlighterManager.clear(); }

    /**
     * Moves the current match index by the provided delta, wrapping around.
     * <p>
     * @param delta offset to apply (positive for next, negative for previous)
     */
    private void jumpMatch(int delta) {
        if (matches.isEmpty()) return;
        matchIndex = (matchIndex + delta) % matches.size();
        if (matchIndex < 0) matchIndex += matches.size();
        revealMatch(matchIndex);
        updateMatchCount();
    }

    /**
     * Ensures the indexed match is visible in the viewport.
     * <p>
     * @param i match index to reveal
     */
    private void revealMatch(int i) {
        if (i < 0 || i >= matches.size()) return;
        int[] m = matches.get(i);
        ensureVisible(m[0]);
    }

    /**
     * Scrolls the viewport to the given document offset.
     * <p>
     * @param offset document offset to reveal
     */
    private void ensureVisible(int offset) {
        try {
            var r2d = logTextPane.modelToView2D(offset);
            if (r2d != null) logTextPane.scrollRectToVisible(r2d.getBounds());
        } catch (Exception ex) {
            Logger.internalDebug("LogPanel ensureVisible failed: " + ex);
        }
    }

    /**
     * Updates the match count label based on current search state.
     */
    private void updateMatchCount() {
        int total = matches == null ? 0 : matches.size();
        int idx1 = (matchIndex >= 0 && total > 0) ? (matchIndex + 1) : 0;
        searchCountLabel.setText(idx1 + "/" + total);
    }

    // ---- Copy/Save ----

    /**
     * Copies the current selection when present; otherwise copies the entire log.
     */
    private void copySelectionOrAll() {
        String sel = logTextPane.getSelectedText();
        if (sel != null && !sel.isEmpty()) {
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(new StringSelection(sel), null);
            return;
        }
        copyAll();
    }

    /**
     * Copies only the current selection to the system clipboard.
     */
    private void copySelection() {
        String sel = logTextPane.getSelectedText();
        if (sel == null || sel.isEmpty()) return;
        Toolkit.getDefaultToolkit()
                .getSystemClipboard()
                .setContents(new StringSelection(sel), null);
    }

    /**
     * Copies the line at the caret position to the system clipboard.
     */
    private void copyCurrentLine() {
        try {
            int caret = logTextPane.getCaretPosition();
            String text = logTextPane.getDocument().getText(0, logTextPane.getDocument().getLength());
            int start = text.lastIndexOf('\n', Math.max(0, caret - 1)) + 1;
            int end = text.indexOf('\n', caret);
            if (end < 0) end = text.length();
            String line = text.substring(start, end);
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(new StringSelection(line), null);
        } catch (Exception ex) {
            Logger.internalDebug("LogPanel copy current line failed: " + ex);
        }
    }

    /**
     * Copies the entire log contents to the system clipboard.
     */
    private void copyAll() {
        try {
            String all = logTextPane.getDocument().getText(0, logTextPane.getDocument().getLength());
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(new StringSelection(all), null);
        } catch (Exception ex) {
            Logger.internalDebug("LogPanel copy all failed: " + ex);
        }
    }

    /**
     * Saves the currently visible log to a user-selected file.
     * <p>
     * EDT only.
     */
    private void saveVisible() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Log");
        String ts = java.time.format.DateTimeFormatter
                .ofPattern("yyyyMMdd-HHmmss")
                .format(java.time.LocalDateTime.now());
        chooser.setSelectedFile(new File("attackframework-burp-exporter-" + ts + ".log"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File out = chooser.getSelectedFile();
        try {
            String text = logTextPane.getDocument().getText(0, logTextPane.getDocument().getLength());
            FileUtil.writeStringCreateDirs(out.toPath(), text);
        } catch (IOException | javax.swing.text.BadLocationException ex) {
            Logger.logError("Save failed: " + ex.getMessage());
        }
    }

    private JPopupMenu buildContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copySel = new JMenuItem("Copy selection");
        JMenuItem copyLine = new JMenuItem("Copy current line");
        JMenuItem copyAll = new JMenuItem("Copy all");
        JMenuItem saveVisible = new JMenuItem("Save visible…");
        copySel.addActionListener(e -> copySelection());
        copyLine.addActionListener(e -> copyCurrentLine());
        copyAll.addActionListener(e -> copyAll());
        menu.add(copySel);
        menu.add(copyLine);
        menu.add(copyAll);
        menu.addSeparator();
        menu.add(saveVisible);
        return menu;
    }
}
