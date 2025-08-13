package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.sinks.OpenSearchSink;
import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.Json;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import net.miginfocom.swing.MigLayout;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.undo.UndoManager;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * UI for selecting sources/scope, configuring sinks, kicking off small actions,
 * and surfacing status. Comments favor intent/design over narration.
 */
public class ConfigPanel extends JPanel {

    // Layout & status sizing constants
    private static final int INDENT = 30;
    private static final int ROW_GAP = 15;
    private static final int STATUS_MIN_COLS = 20;
    private static final int STATUS_MAX_COLS = 200;

    // Sources
    private final JCheckBox settingsCheckbox = new JCheckBox("Settings", true);
    private final JCheckBox sitemapCheckbox  = new JCheckBox("Sitemap",  true);
    private final JCheckBox issuesCheckbox   = new JCheckBox("Issues",   true);
    private final JCheckBox trafficCheckbox  = new JCheckBox("Traffic",  true);

    // Scope
    private final JRadioButton allRadio       = new JRadioButton("All");
    private final JRadioButton burpSuiteRadio = new JRadioButton("Burp Suite's", true);
    private final JRadioButton customRadio    = new JRadioButton("Custom (RegEx)");
    private final JTextField   customScopeField = new JTextField("^.*acme\\.com$");

    // Files sink
    private final JCheckBox fileSinkCheckbox = new JCheckBox("Files", true);
    private final JTextField filePathField   = new AutoSizingTextField("/path/to/directory");
    private final JButton    createFilesButton = new JButton("Create Files");
    private final JTextArea  fileStatus = new JTextArea();
    private final JPanel     fileStatusWrapper = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));

    // OpenSearch sink
    private final JCheckBox openSearchSinkCheckbox = new JCheckBox("OpenSearch", false);
    private final JTextField openSearchUrlField    = new AutoSizingTextField("http://opensearch.url:9200");
    private final JButton    testConnectionButton  = new JButton("Test Connection");
    private final JButton    createIndexesButton   = new JButton("Create Indexes");
    private final JTextArea  openSearchStatus      = new JTextArea();
    private final JPanel     statusWrapper         = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));

    // Admin status areas
    private final JTextArea adminStatus = new JTextArea();
    private final JPanel    adminStatusWrapper = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));
    private Timer adminStatusHideTimer;

    private final JTextArea importExportStatus = new JTextArea();
    private final JPanel    importExportStatusWrapper = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));

    /** Build the panel and wire actions. */
    public ConfigPanel() {
        setLayout(new MigLayout("fillx, insets 12", "[fill]"));

        add(buildSourcesPanel(), "gaptop 5, gapbottom 5, wrap");
        add(panelSeparator(), "growx, wrap");

        add(buildScopePanel(), "gaptop 10, gapbottom 5, wrap");
        add(panelSeparator(), "growx, wrap");

        add(buildSinksPanel(), "gaptop 10, gapbottom 5, wrap");
        add(panelSeparator(), "growx, wrap");

        add(buildAdminPanel(), "growx, wrap");
        add(Box.createVerticalGlue(), "growy, wrap");

        assignComponentNames();     // stable identifiers for tests
        wireTextFieldEnhancements(); // undo/redo + Enter bindings
        refreshEnabledStates();      // reflect current checkbox state
    }

    /** Sources section. */
    private JPanel buildSourcesPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        panel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel header = new JLabel("Data Sources");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        panel.add(settingsCheckbox, "gapleft " + INDENT);
        panel.add(sitemapCheckbox,  "gapleft " + INDENT);
        panel.add(issuesCheckbox,   "gapleft " + INDENT);
        panel.add(trafficCheckbox,  "gapleft " + INDENT);

        return panel;
    }

    /** Scope selection (Burp scope, Custom regex, or All). */
    private JPanel buildScopePanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        panel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel header = new JLabel("Scope");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(burpSuiteRadio);
        scopeGroup.add(customRadio);
        scopeGroup.add(allRadio);

        panel.add(burpSuiteRadio, "gapleft " + INDENT);

        JPanel customRow = new JPanel(new MigLayout("insets 0", "[]20[]", ""));
        customRow.add(customRadio);
        customRow.add(customScopeField);
        panel.add(customRow, "gapleft " + INDENT);

        panel.add(allRadio, "gapleft " + INDENT);

        return panel;
    }

    /** Sinks section (Files, OpenSearch) and status areas. */
    private JPanel buildSinksPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[grow]", "[]"+ROW_GAP+"[]"+ROW_GAP+"[]"));
        panel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel header = new JLabel("Data Sinks");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6, wrap");

        JPanel fileRow = new JPanel(new MigLayout("insets 0", "[150!, left]20[pref]20[left]20[left, grow]"));
        fileRow.setAlignmentX(LEFT_ALIGNMENT);

        fileRow.add(fileSinkCheckbox, "gapleft " + INDENT + ", alignx left, top");
        fileRow.add(filePathField,    "alignx left, top");
        fileRow.add(createFilesButton, "alignx left, top");

        configureTextArea(fileStatus);
        fileStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        fileStatusWrapper.removeAll();
        fileStatusWrapper.add(fileStatus, "w pref!");
        fileStatusWrapper.setVisible(false);
        fileRow.add(fileStatusWrapper, "hidemode 3, alignx left, w pref!, wrap");
        panel.add(fileRow, "growx, wrap");

        JPanel openSearchRow = new JPanel(new MigLayout("insets 0", "[150!, left]20[pref]20[left]20[left, grow]"));
        openSearchRow.setAlignmentX(LEFT_ALIGNMENT);

        openSearchRow.add(openSearchSinkCheckbox, "gapleft " + INDENT + ", top");
        openSearchRow.add(openSearchUrlField,     "alignx left, top");
        openSearchRow.add(testConnectionButton,   "split 2, alignx left, top");
        openSearchRow.add(createIndexesButton,    "gapleft 15, alignx left, top");

        configureTextArea(openSearchStatus);
        statusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        statusWrapper.removeAll();
        statusWrapper.add(openSearchStatus, "w pref!");
        statusWrapper.setVisible(false);
        openSearchRow.add(statusWrapper, "hidemode 3, alignx left, w pref!, wrap");
        panel.add(openSearchRow, "growx, wrap");

        wireButtonActions();
        return panel;
    }

    /** Admin section with Import/Export row and Save functionality. */
    private JPanel buildAdminPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[left]", "[]"+ROW_GAP+"[]"));
        panel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel header = new JLabel("Admin");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        JPanel importExportRow = new JPanel(new MigLayout("insets 0", "[]15[]15[left, grow]", ""));
        JButton importButton = new JButton("Import Config");
        JButton exportButton = new JButton("Export Config");
        importButton.addActionListener(e -> doImportConfig());
        exportButton.addActionListener(e -> doExportConfig());
        importExportRow.add(importButton);
        importExportRow.add(exportButton);

        configureTextArea(importExportStatus);
        importExportStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        importExportStatusWrapper.removeAll();
        importExportStatusWrapper.add(importExportStatus, "w pref!");
        importExportStatusWrapper.setVisible(false);
        importExportRow.add(importExportStatusWrapper, "hidemode 3, alignx left, w pref!, wrap");

        panel.add(importExportRow, "gapleft " + INDENT + ", wrap");

        JPanel row = new JPanel(new MigLayout("insets 0", "[]", ""));
        JButton adminSaveButton = new JButton("Save");
        adminSaveButton.addActionListener(new AdminSaveButtonListener());
        row.add(adminSaveButton);

        configureTextArea(adminStatus);
        adminStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        adminStatusWrapper.removeAll();
        adminStatusWrapper.add(adminStatus, "w pref!");
        adminStatusWrapper.setVisible(false);
        row.add(adminStatusWrapper, "hidemode 3, alignx left, w pref!, wrap");

        panel.add(row, "gapleft " + INDENT);
        return panel;
    }

    /** 2px horizontal separator. */
    private JComponent panelSeparator() {
        return new JSeparator() {
            @Override public Dimension getPreferredSize() {
                return new Dimension(super.getPreferredSize().width, 2);
            }
            @Override protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(getForeground());
                g.fillRect(0, 1, getWidth(), 2);
            }
        };
    }

    /** Monospace, non-wrapping status areas for predictable layout. */
    private void configureTextArea(JTextArea area) {
        area.setEditable(false);
        area.setLineWrap(false);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setFont(new Font("Monospaced", Font.PLAIN, 12));
        area.setRows(1);
        area.setColumns(1);
    }

    // ---- DRY status updaters ----
    private static void setStatus(JTextArea area, JPanel wrapper, String message) {
        area.setText(message);
        String[] lines = message.split("\r\n|\r|\n", -1);
        int rows = Math.max(lines.length, 1);
        int cols = Math.min(STATUS_MAX_COLS, Math.max(STATUS_MIN_COLS, maxLineLength(lines)));
        area.setRows(rows);
        area.setColumns(cols);
        wrapper.setVisible(true);
        wrapper.revalidate();
        wrapper.repaint();
    }
    private void updateStatus(String message) { setStatus(openSearchStatus, statusWrapper, message); }
    private void updateFileStatus(String message) { setStatus(fileStatus, fileStatusWrapper, message); }
    private void updateAdminStatus(String message) { setStatus(adminStatus, adminStatusWrapper, message); }
    private void updateImportExportStatus(String message) { setStatus(importExportStatus, importExportStatusWrapper, message); }

    private static int maxLineLength(String[] lines) {
        int max = 1;
        for (String s : lines) if (s != null && s.length() > max) max = s.length();
        return max;
    }

    /** Button actions and enable/disable UX. */
    private void wireButtonActions() {
        fileSinkCheckbox.addItemListener(e -> refreshEnabledStates());
        openSearchSinkCheckbox.addItemListener(e -> refreshEnabledStates());

        createFilesButton.addActionListener(e -> {
            String root = filePathField.getText().trim();
            if (root.isEmpty()) {
                updateFileStatus("✖ Path required");
                return;
            }
            updateFileStatus("Creating files in " + root + " ...");
            createFilesButton.setEnabled(false);

            new SwingWorker<List<FileUtil.CreateResult>, Void>() {
                @Override protected List<FileUtil.CreateResult> doInBackground() {
                    List<String> baseNames = IndexNaming.computeIndexBaseNames(getSelectedSources());
                    List<String> jsonNames = IndexNaming.toJsonFileNames(baseNames);
                    return FileUtil.ensureJsonFiles(root, jsonNames);
                }
                @Override protected void done() {
                    try {
                        List<FileUtil.CreateResult> results = get();
                        List<String> created = new ArrayList<>();
                        List<String> exists  = new ArrayList<>();
                        List<String> failed  = new ArrayList<>();
                        for (FileUtil.CreateResult r : results) {
                            switch (r.status()) {
                                case CREATED -> created.add(r.path().toString());
                                case EXISTS  -> exists.add(r.path().toString());
                                case FAILED  -> failed.add(r.path().toString() + " — " + r.error());
                            }
                        }
                        StringBuilder sb = new StringBuilder();
                        if (!created.isEmpty()) {
                            sb.append(created.size() == 1 ? "File created:\n  " : "Files created:\n  ")
                                    .append(String.join("\n  ", created)).append("\n");
                        }
                        if (!exists.isEmpty()) {
                            sb.append(exists.size() == 1 ? "File already existed:\n  " : "Files already existed:\n  ")
                                    .append(String.join("\n  ", exists)).append("\n");
                        }
                        if (!failed.isEmpty()) {
                            sb.append(failed.size() == 1 ? "File creation failed:\n  " : "File creations failed:\n  ")
                                    .append(String.join("\n  ", failed)).append("\n");
                        }
                        updateFileStatus(sb.toString().trim());
                    } catch (Exception ex) {
                        updateFileStatus("File creation error: " + ex.getMessage());
                        Logger.logError("File creation error: " + ex.getMessage());
                    } finally {
                        createFilesButton.setEnabled(true);
                    }
                }
            }.execute();
        });

        testConnectionButton.addActionListener(e -> {
            String url = openSearchUrlField.getText().trim();
            if (url.isEmpty()) {
                updateStatus("✖ URL required");
                return;
            }
            updateStatus("Testing ...");
            testConnectionButton.setEnabled(false);

            new SwingWorker<OpenSearchClientWrapper.OpenSearchStatus, Void>() {
                @Override protected OpenSearchClientWrapper.OpenSearchStatus doInBackground() {
                    return OpenSearchClientWrapper.safeTestConnection(url);
                }
                @Override protected void done() {
                    try {
                        OpenSearchClientWrapper.OpenSearchStatus status = get();
                        if (status.success()) {
                            updateStatus(status.message() + " (" + status.distribution() + " v" + status.version() + ")");
                            Logger.logInfo("OpenSearch connection successful: " + status.message()
                                    + " (" + status.distribution() + " v" + status.version() + ") at " + url);
                        } else {
                            updateStatus("✖ " + status.message());
                            Logger.logError("OpenSearch connection failed: " + status.message());
                        }
                    } catch (Exception ex) {
                        updateStatus("✖ Error: " + ex.getMessage());
                        Logger.logError("OpenSearch connection error: " + ex.getMessage());
                    } finally {
                        testConnectionButton.setEnabled(true);
                    }
                }
            }.execute();
        });

        createIndexesButton.addActionListener(e -> {
            String url = openSearchUrlField.getText().trim();
            if (url.isEmpty()) {
                updateStatus("✖ URL required");
                return;
            }
            updateStatus("Creating indexes . . .");
            createIndexesButton.setEnabled(false);

            new SwingWorker<List<IndexResult>, Void>() {
                @Override protected List<IndexResult> doInBackground() {
                    return OpenSearchSink.createSelectedIndexes(url, getSelectedSources());
                }
                @Override protected void done() {
                    try {
                        List<IndexResult> results = get();
                        List<String> created = new ArrayList<>();
                        List<String> exists  = new ArrayList<>();
                        List<String> failed  = new ArrayList<>();
                        for (IndexResult r : results) {
                            switch (r.status()) {
                                case CREATED -> created.add(r.fullName());
                                case EXISTS  -> exists.add(r.fullName());
                                case FAILED  -> failed.add(r.fullName());
                            }
                        }
                        boolean allExist = !results.isEmpty() &&
                                results.stream().allMatch(r -> r.status() == IndexResult.Status.EXISTS);

                        StringBuilder sb = new StringBuilder();
                        if (!created.isEmpty()) {
                            sb.append(created.size() == 1 ? "Index created:\n  " : "Indexes created:\n  ")
                                    .append(String.join("\n  ", created)).append("\n");
                        }
                        if (!exists.isEmpty()) {
                            sb.append(exists.size() == 1 ? "Index already existed:\n  " : "Indexes already existed:\n  ")
                                    .append(String.join("\n  ", exists)).append("\n");
                        }
                        if (!failed.isEmpty()) {
                            sb.append(failed.size() == 1 ? "Index failed:\n  " : "Indexes failed:\n  ")
                                    .append(String.join("\n  ", failed)).append("\n");
                        }

                        if (allExist) Logger.logInfo("All indexes already existed — no creation performed.");
                        updateStatus(sb.toString().trim());
                    } catch (Exception ex) {
                        updateStatus("Index creation error: " + ex.getMessage());
                        Logger.logError("Index creation error: " + ex.getMessage());
                    } finally {
                        createIndexesButton.setEnabled(true);
                    }
                }
            }.execute();
        });

        // Keep text fields sized to content while typing.
        DocumentListener relayout = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
            public void removeUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
            public void changedUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
        };
        filePathField.getDocument().addDocumentListener(relayout);
        openSearchUrlField.getDocument().addDocumentListener(relayout);
    }

    /** Reflect sink checkboxes in control enablement. */
    private void refreshEnabledStates() {
        boolean files = fileSinkCheckbox.isSelected();
        filePathField.setEnabled(files);
        createFilesButton.setEnabled(files);

        boolean os = openSearchSinkCheckbox.isSelected();
        openSearchUrlField.setEnabled(os);
    }

    /** Short names used to compute index basenames. */
    private List<String> getSelectedSources() {
        List<String> selected = new ArrayList<>();
        if (settingsCheckbox.isSelected()) selected.add("settings");
        if (sitemapCheckbox.isSelected())  selected.add("sitemap");
        if (issuesCheckbox.isSelected())   selected.add("findings");
        if (trafficCheckbox.isSelected())  selected.add("traffic");
        return selected;
    }

    /** Text field that sizes to its content. */
    private static class AutoSizingTextField extends JTextField {
        public AutoSizingTextField(String text) { super(text); }
        @Override public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            int textWidth = fm.stringWidth(getText()) + 20;
            int height = super.getPreferredSize().height;
            return new Dimension(textWidth, height);
        }
    }

    /** Save logs a pretty JSON snapshot of current UI (non-secret settings only). */
    private class AdminSaveButtonListener implements ActionListener {
        @Override public void actionPerformed(ActionEvent e) {
            try {
                String json = currentConfigJson();
                Logger.logInfo("Saving config ...");
                Logger.logInfo(json);

                updateAdminStatus("Saved!");
                if (adminStatusHideTimer != null && adminStatusHideTimer.isRunning()) adminStatusHideTimer.stop();
                adminStatusHideTimer = new Timer(3000, evt -> {
                    adminStatusWrapper.setVisible(false);
                    adminStatusWrapper.revalidate();
                    adminStatusWrapper.repaint();
                });
                adminStatusHideTimer.setRepeats(false);
                adminStatusHideTimer.start();

            } catch (Exception ex) {
                updateAdminStatus("✖ Error: " + ex.getMessage());
                Logger.logError("Admin save error: " + ex.getMessage());
            }
        }
    }

    /** Build pretty JSON of current UI state (non-secret). */
    private String currentConfigJson() {
        List<String> selectedSources = getSelectedSources();

        String scopeType;
        List<String> scopeRegexes = null;
        if (allRadio.isSelected()) {
            scopeType = "all";
        } else if (burpSuiteRadio.isSelected()) {
            scopeType = "burp";
        } else {
            scopeType = "custom";
            scopeRegexes = new ArrayList<>();
            String rx = customScopeField.getText();
            if (rx != null && !rx.trim().isEmpty()) scopeRegexes.add(rx.trim());
        }

        boolean filesEnabled = fileSinkCheckbox.isSelected();
        boolean osEnabled    = openSearchSinkCheckbox.isSelected();
        String  osUrl        = openSearchUrlField.getText();
        String  filesRoot    = filePathField.getText();

        return Json.buildPrettyConfigJson(
                selectedSources, scopeType, scopeRegexes,
                filesEnabled, filesRoot, osEnabled, osUrl
        );
    }

    /** Text-input UX: undo/redo + Enter-to-action. */
    private void wireTextFieldEnhancements() {
        installUndoRedo(filePathField);
        installUndoRedo(openSearchUrlField);
        installUndoRedo(customScopeField);

        // Enter on these fields triggers the relevant action
        filePathField.addActionListener(e -> createFilesButton.doClick());
        openSearchUrlField.addActionListener(e -> testConnectionButton.doClick());
    }

    /** Undo/redo on a text field via key bindings. */
    private static void installUndoRedo(JTextField field) {
        UndoManager undo = new UndoManager();
        undo.setLimit(200);
        field.getDocument().addUndoableEditListener(undo);

        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK), "undo");
        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.META_DOWN_MASK), "undo");

        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Y, KeyEvent.CTRL_DOWN_MASK), "redo");
        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Y, KeyEvent.META_DOWN_MASK), "redo");
        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK), "redo");
        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.META_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK), "redo");

        field.getActionMap().put("undo", new AbstractAction() { @Override public void actionPerformed(ActionEvent e) { if (undo.canUndo()) undo.undo(); }});
        field.getActionMap().put("redo", new AbstractAction() { @Override public void actionPerformed(ActionEvent e) { if (undo.canRedo()) undo.redo(); }});
    }

    private static void bind(JTextField field, KeyStroke ks, String actionKey) {
        field.getInputMap(JComponent.WHEN_FOCUSED).put(ks, actionKey);
    }

    // --------------------------
    // Import / Export
    // --------------------------

    /** Export current JSON to a file via chooser. */
    private void doExportConfig() {
        String json = currentConfigJson();

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        chooser.setSelectedFile(new File("attackframework-burp-exporter-config.json"));

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            updateImportExportStatus("Export cancelled.");
            return;
        }

        File file = FileUtil.ensureJsonExtension(chooser.getSelectedFile());
        try {
            FileUtil.writeStringCreateDirs(file.toPath(), json);
            updateImportExportStatus("Exported to " + file.getAbsolutePath());
            Logger.logInfo("Config exported to " + file.getAbsolutePath());
        } catch (IOException ioe) {
            updateImportExportStatus("✖ Export error: " + ioe.getMessage());
            Logger.logError("Export error: " + ioe.getMessage());
        }
    }

    /** Import JSON from a file via chooser and apply it to the UI. */
    private void doImportConfig() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));

        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            updateImportExportStatus("Import cancelled.");
            return;
        }

        File file = chooser.getSelectedFile();
        try {
            String json = FileUtil.readString(file.toPath());
            Json.ImportedConfig cfg = Json.parseConfigJson(json);
            applyImported(cfg);

            refreshEnabledStates();
            updateImportExportStatus("Imported from " + file.getAbsolutePath());
            Logger.logInfo("Config imported from " + file.getAbsolutePath());

            if ("custom".equals(cfg.scopeType) && cfg.scopeRegexes.size() > 1) {
                Logger.logInfo("Imported multiple custom regex entries; using the first. Additional fields will be supported later.");
            }

        } catch (Exception ex) {
            updateImportExportStatus("✖ Import error: " + ex.getMessage());
            Logger.logError("Import error: " + ex.getMessage());
        }
    }

    // ---- chooser-free helpers (package-private for tests) ----

    void exportConfigTo(Path out) throws IOException {
        FileUtil.writeStringCreateDirs(out, currentConfigJson());
        Logger.logInfo("Config exported to " + out.toAbsolutePath());
    }

    void importConfigFrom(Path in) throws IOException {
        String json = FileUtil.readString(in);
        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        applyImported(cfg);
        refreshEnabledStates();
        Logger.logInfo("Config imported from " + in.toAbsolutePath());
    }

    // ---- internal: apply imported values to the UI ----

    private void applyImported(Json.ImportedConfig cfg) {
        // Sources
        settingsCheckbox.setSelected(cfg.dataSources.contains("settings"));
        sitemapCheckbox.setSelected(cfg.dataSources.contains("sitemap"));
        issuesCheckbox.setSelected(cfg.dataSources.contains("findings"));
        trafficCheckbox.setSelected(cfg.dataSources.contains("traffic"));

        // Scope
        switch (cfg.scopeType) {
            case "custom" -> {
                customRadio.setSelected(true);
                customScopeField.setText(cfg.scopeRegexes.isEmpty() ? "" : cfg.scopeRegexes.getFirst());
            }
            case "burp" -> burpSuiteRadio.setSelected(true);
            default -> allRadio.setSelected(true); // "all"
        }

        // Sinks
        if (cfg.filesPath != null) {
            fileSinkCheckbox.setSelected(true);
            filePathField.setText(cfg.filesPath);
        } else {
            fileSinkCheckbox.setSelected(false);
        }
        if (cfg.openSearchUrl != null) {
            openSearchSinkCheckbox.setSelected(true);
            openSearchUrlField.setText(cfg.openSearchUrl);
        } else {
            openSearchSinkCheckbox.setSelected(false);
        }
    }

    /** Assign stable names so tests don't rely on visible labels. */
    private void assignComponentNames() {
        // sources
        settingsCheckbox.setName("src.settings");
        sitemapCheckbox.setName("src.sitemap");
        issuesCheckbox.setName("src.issues");
        trafficCheckbox.setName("src.traffic");

        // scope
        allRadio.setName("scope.all");
        burpSuiteRadio.setName("scope.burp");
        customRadio.setName("scope.custom");
        customScopeField.setName("scope.custom.regex");

        // files sink
        fileSinkCheckbox.setName("files.enable");
        filePathField.setName("files.path");
        createFilesButton.setName("files.create");

        // opensearch sink
        openSearchSinkCheckbox.setName("os.enable");
        openSearchUrlField.setName("os.url");
        testConnectionButton.setName("os.test");
        createIndexesButton.setName("os.createIndexes");
    }
}
