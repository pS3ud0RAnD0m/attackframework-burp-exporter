package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.sinks.OpenSearchSink;
import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.files.FilesUtil;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.attackframework.tools.burp.utils.IndexNaming;
import net.miginfocom.swing.MigLayout;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.KeyStroke;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
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
import java.awt.GraphicsEnvironment;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UI for selecting sources/scope, configuring sinks, running small actions,
 * and logging/surfacing status. Comments are concise and focus on intent/design.
 */
public class ConfigPanel extends JPanel {

    // Layout & status sizing constants
    private static final int INDENT = 30;
    private static final int ROW_GAP = 15;
    private static final int STATUS_MIN_COLS = 20;
    private static final int STATUS_MAX_COLS = 200;

    private final JCheckBox settingsCheckbox = new JCheckBox("Settings", true);
    private final JCheckBox sitemapCheckbox  = new JCheckBox("Sitemap",  true);
    private final JCheckBox issuesCheckbox   = new JCheckBox("Issues",   true);
    private final JCheckBox trafficCheckbox  = new JCheckBox("Traffic",  true);

    private final JRadioButton allRadio       = new JRadioButton("All");
    private final JRadioButton burpSuiteRadio = new JRadioButton("Burp Suite's", true);
    private final JRadioButton customRadio    = new JRadioButton("Custom (RegEx)");
    private final JTextField   customScopeField = new JTextField("^.*acme\\.com$");

    private final JCheckBox fileSinkCheckbox = new JCheckBox("Files", true);
    private final JTextField filePathField   = new AutoSizingTextField("/path/to/directory");
    private final JButton    createFilesButton = new JButton("Create Files");
    private final JTextArea  fileStatus = new JTextArea();
    private final JPanel     fileStatusWrapper = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));

    private final JCheckBox openSearchSinkCheckbox = new JCheckBox("OpenSearch", false);
    private final JTextField openSearchUrlField    = new AutoSizingTextField("http://opensearch.url:9200");
    private final JButton    testConnectionButton  = new JButton("Test Connection");
    private final JButton    createIndexesButton   = new JButton("Create Indexes");
    private final JTextArea  openSearchStatus      = new JTextArea();
    private final JPanel     statusWrapper         = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));

    // Admin Save status UI (hidden until Save is clicked).
    private final JTextArea adminStatus = new JTextArea();
    private final JPanel    adminStatusWrapper = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));
    private Timer adminStatusHideTimer;

    // Admin Import/Export status UI (hidden until either button is clicked).
    private final JTextArea importExportStatus = new JTextArea();
    private final JPanel    importExportStatusWrapper = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));

    /**
     * Creates a new ConfigPanel.
     */
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

        // Text-input UX: install undo/redo and Enter-to-action bindings.
        wireTextFieldEnhancements();

        // Initialize enabled/disabled state based on checkboxes.
        refreshEnabledStates();
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

        JPanel fileRow = new JPanel(new MigLayout(
                "insets 0",
                "[150!, left]20[pref]20[left]20[left, grow]"
        ));
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

        JPanel openSearchRow = new JPanel(new MigLayout(
                "insets 0",
                "[150!, left]20[pref]20[left]20[left, grow]"
        ));
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

        // Row 1: Import/Export + status (hidden until used)
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

        // indent to match other panels
        panel.add(importExportRow, "gapleft " + INDENT + ", wrap");

        // Row 2: Save + status (hidden until used)
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

        // indent to match other panels
        panel.add(row, "gapleft " + INDENT);

        return panel;
    }

    /** 2px horizontal separator for section delineation. */
    private JComponent panelSeparator() {
        return new JSeparator() {
            @Override
            public Dimension getPreferredSize() {
                return new Dimension(super.getPreferredSize().width, 2);
            }

            @Override
            protected void paintComponent(Graphics g) {
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

    // ---- DRY status updater helpers ----
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

    /** Button actions and small enable/disable UX. */
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

            new SwingWorker<List<FilesUtil.CreateResult>, Void>() {
                @Override
                protected List<FilesUtil.CreateResult> doInBackground() {
                    List<String> baseNames = IndexNaming.computeIndexBaseNames(getSelectedSources());
                    List<String> jsonNames = IndexNaming.toJsonFileNames(baseNames);
                    // Delegate full file creation to FilesUtil (String overload avoids Path construction here)
                    return FilesUtil.ensureJsonFiles(root, jsonNames);
                }
                @Override
                protected void done() {
                    try {
                        List<FilesUtil.CreateResult> results = get();

                        List<String> created = new ArrayList<>();
                        List<String> exists  = new ArrayList<>();
                        List<String> failed  = new ArrayList<>();

                        for (FilesUtil.CreateResult r : results) {
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
                @Override
                protected OpenSearchClientWrapper.OpenSearchStatus doInBackground() {
                    return OpenSearchClientWrapper.safeTestConnection(url);
                }
                @Override
                protected void done() {
                    try {
                        OpenSearchClientWrapper.OpenSearchStatus status = get();
                        if (status.success()) {
                            updateStatus(status.message() + " (" + status.distribution() + " v" + status.version() + ")");
                            Logger.logInfo("OpenSearch connection successful: " + status.message() +
                                    " (" + status.distribution() + " v" + status.version() + ") at " + url);
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
                @Override
                protected List<IndexResult> doInBackground() {
                    return OpenSearchSink.createSelectedIndexes(url, getSelectedSources());
                }
                @Override
                protected void done() {
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

        // Keep text fields sizing to content as user types.
        DocumentListener relayout = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
            public void removeUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
            public void changedUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
        };
        filePathField.getDocument().addDocumentListener(relayout);
        openSearchUrlField.getDocument().addDocumentListener(relayout);
    }

    /** Toggle enabled state of controls based on sink checkboxes. */
    private void refreshEnabledStates() {
        boolean files = fileSinkCheckbox.isSelected();
        filePathField.setEnabled(files);
        createFilesButton.setEnabled(files);

        boolean os = openSearchSinkCheckbox.isSelected();
        openSearchUrlField.setEnabled(os);
    }

    /** Selected short names used to compute index basenames. */
    private List<String> getSelectedSources() {
        List<String> selected = new ArrayList<>();
        if (settingsCheckbox.isSelected()) selected.add("settings");
        if (sitemapCheckbox.isSelected())  selected.add("sitemap");
        if (issuesCheckbox.isSelected())   selected.add("findings");
        if (trafficCheckbox.isSelected())  selected.add("traffic");
        return selected;
    }

    /** Text field that computes preferred width from its content. */
    private static class AutoSizingTextField extends JTextField {
        public AutoSizingTextField(String text) { super(text); }
        @Override public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            int textWidth = fm.stringWidth(getText()) + 20;
            int height = super.getPreferredSize().height;
            return new Dimension(textWidth, height);
        }
    }

    /** Save (Admin) logs selected sources, scope, and sinks as pretty JSON. */
    private class AdminSaveButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
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

    /** Build JSON snapshot of current UI (non-secret settings only). */
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

        return buildPrettyConfigJson(
                selectedSources,
                scopeType,
                scopeRegexes,
                filesEnabled,
                filesRoot,
                osEnabled,
                osUrl
        );
    }

    /**
     * Text-field UX:
     *  - Undo/Redo: bind both Ctrl and Meta variants (plus Shift+Z redo), headless-safe.
     *  - Enter on filePathField -> clicks Create Files
     *  - Enter on openSearchUrlField -> clicks Test Connection
     */
    private void wireTextFieldEnhancements() {
        installUndoRedo(filePathField);
        installUndoRedo(openSearchUrlField);
        installUndoRedo(customScopeField);

        filePathField.addActionListener(e -> createFilesButton.doClick());
        openSearchUrlField.addActionListener(e -> testConnectionButton.doClick());
    }

    /** Robust, headless-safe undo/redo on a text field using key bindings + UndoManager. */
    private static void installUndoRedo(JTextField field) {
        UndoManager undo = new UndoManager();
        undo.setLimit(200);
        field.getDocument().addUndoableEditListener(undo);

        // Undo
        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK), "undo");
        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.META_DOWN_MASK), "undo");
        // Redo
        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Y, KeyEvent.CTRL_DOWN_MASK), "redo");
        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Y, KeyEvent.META_DOWN_MASK), "redo");
        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK), "redo");
        bind(field, KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.META_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK), "redo");

        field.getActionMap().put("undo", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { if (undo.canUndo()) undo.undo(); }
        });
        field.getActionMap().put("redo", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { if (undo.canRedo()) undo.redo(); }
        });
    }

    private static void bind(JTextField field, KeyStroke ks, String actionKey) {
        field.getInputMap(JComponent.WHEN_FOCUSED).put(ks, actionKey);
    }

    // --------------------------
    // Import / Export wiring
    // --------------------------

    /** Export current JSON to a file (headless-safe: writes to temp). */
    private void doExportConfig() {
        String json = currentConfigJson();

        if (GraphicsEnvironment.isHeadless()) {
            try {
                Path out = FilesUtil.writeTempFile("attackframework-config-export-", ".json", json);
                updateImportExportStatus("Exported to " + out.toAbsolutePath());
                Logger.logInfo("Config exported (headless) to " + out.toAbsolutePath());
            } catch (IOException ioe) {
                updateImportExportStatus("✖ Export error: " + ioe.getMessage());
                Logger.logError("Export error: " + ioe.getMessage());
            }
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        chooser.setSelectedFile(new File("attackframework-config.json"));

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            updateImportExportStatus("Export cancelled.");
            return;
        }

        File file = FilesUtil.ensureJsonExtension(chooser.getSelectedFile());
        try {
            FilesUtil.writeStringCreateDirs(file.toPath(), json);
            updateImportExportStatus("Exported to " + file.getAbsolutePath());
            Logger.logInfo("Config exported to " + file.getAbsolutePath());
        } catch (IOException ioe) {
            updateImportExportStatus("✖ Export error: " + ioe.getMessage());
            Logger.logError("Export error: " + ioe.getMessage());
        }
    }

    /** Import JSON from a file and apply it to the UI. */
    private void doImportConfig() {
        if (GraphicsEnvironment.isHeadless()) {
            updateImportExportStatus("✖ Import not available in headless mode.");
            Logger.logError("Import attempted in headless mode.");
            return;
        }

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
            String json = FilesUtil.readString(file.toPath());
            ImportedConfig cfg = parseConfigJson(json);

            // Apply to UI (sources)
            settingsCheckbox.setSelected(cfg.dataSources.contains("settings"));
            sitemapCheckbox.setSelected(cfg.dataSources.contains("sitemap"));
            issuesCheckbox.setSelected(cfg.dataSources.contains("findings"));
            trafficCheckbox.setSelected(cfg.dataSources.contains("traffic"));

            // Apply scope
            switch (cfg.scopeType) {
                case "custom" -> {
                    customRadio.setSelected(true);
                    customScopeField.setText(cfg.scopeRegexes.isEmpty() ? "" : cfg.scopeRegexes.getFirst());
                }
                case "burp" -> burpSuiteRadio.setSelected(true);
                default -> allRadio.setSelected(true); // "all"
            }

            // Apply sinks
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

            refreshEnabledStates();
            updateImportExportStatus("Imported from " + file.getAbsolutePath());

            if ("custom".equals(cfg.scopeType) && cfg.scopeRegexes.size() > 1) {
                Logger.logInfo("Imported multiple custom regex entries; using the first. Additional fields will be supported later.");
            }

        } catch (Exception ex) {
            updateImportExportStatus("✖ Import error: " + ex.getMessage());
            Logger.logError("Import error: " + ex.getMessage());
        }
    }

    // --------------------------
    // JSON helpers (export format) and minimal parser
    // --------------------------

    /** Builds a pretty-printed JSON snapshot of current config (non-secret settings only). */
    private static String buildPrettyConfigJson(
            List<String> sources,
            String scopeType,               // "burp" | "custom" | "all"
            List<String> scopeRegexes,      // only when custom; may be empty
            boolean filesEnabled,
            String filesRoot,
            boolean openSearchEnabled,
            String openSearchUrl) {

        String indent = "  ";
        String indent2 = indent + indent;
        String indent3 = indent2 + indent;

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");

        sb.append(indent).append("\"dataSources\": [");
        if (sources != null && !sources.isEmpty()) {
            sb.append("\n");
            for (int i = 0; i < sources.size(); i++) {
                sb.append(indent2).append("\"").append(jsonEscape(sources.get(i))).append("\"");
                if (i < sources.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append(indent).append("],\n");
        } else {
            sb.append("],\n");
        }

        // scope object (tight form): { "custom": [ ... ] } OR { "burp": [] } OR { "all": [] }
        sb.append(indent).append("\"scope\": {\n");
        if ("custom".equals(scopeType)) {
            sb.append(indent2).append("\"custom\": [");
            if (scopeRegexes != null && !scopeRegexes.isEmpty()) {
                sb.append("\n");
                for (int i = 0; i < scopeRegexes.size(); i++) {
                    sb.append(indent3).append("\"").append(jsonEscape(scopeRegexes.get(i))).append("\"");
                    if (i < scopeRegexes.size() - 1) sb.append(",");
                    sb.append("\n");
                }
                sb.append(indent2).append("]\n");
            } else {
                sb.append("]\n");
            }
        } else if ("burp".equals(scopeType)) {
            sb.append(indent2).append("\"burp\": []\n");
        } else {
            sb.append(indent2).append("\"all\": []\n");
        }
        sb.append(indent).append("},\n");

        // sinks — only include selected sinks; values are direct strings (path or URL)
        sb.append(indent).append("\"sinks\": {\n");
        List<String> sinkLines = new ArrayList<>();
        if (filesEnabled) {
            sinkLines.add(indent2 + "\"files\": \"" + jsonEscape(filesRoot != null ? filesRoot : "") + "\"");
        }
        if (openSearchEnabled) {
            sinkLines.add(indent2 + "\"openSearch\": \"" + jsonEscape(openSearchUrl != null ? openSearchUrl : "") + "\"");
        }
        if (!sinkLines.isEmpty()) {
            for (int i = 0; i < sinkLines.size(); i++) {
                sb.append(sinkLines.get(i));
                if (i < sinkLines.size() - 1) sb.append(",\n");
            }
            sb.append("\n").append(indent).append("}\n");
        } else {
            sb.append(indent).append("}\n");
        }

        sb.append("}");
        return sb.toString();
    }

    /** Minimal JSON string escape (quotes, backslashes, common control chars). */
    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.toString();
    }

    // ---- Minimal parser for our export format (no external libs) ----

    private static final class ImportedConfig {
        final List<String> dataSources = new ArrayList<>();
        String scopeType = "all";              // "custom" | "burp" | "all"
        final List<String> scopeRegexes = new ArrayList<>();
        String filesPath;                      // nullable
        String openSearchUrl;                  // nullable
    }

    /**
     * Parses the JSON we export (dataSources array, scope object with custom/burp/all, sinks object).
     * Intentionally minimal and tolerant of whitespace/newlines. Not a general-purpose JSON parser.
     */
    private static ImportedConfig parseConfigJson(String json) {
        ImportedConfig cfg = new ImportedConfig();
        String src = json == null ? "" : json;

        // dataSources: extract ["...","..."]
        Matcher mDs = Pattern.compile("\"dataSources\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL).matcher(src);
        if (mDs.find()) {
            String arr = mDs.group(1);
            Matcher mVals = Pattern.compile("\"(.*?)\"", Pattern.DOTALL).matcher(arr);
            while (mVals.find()) cfg.dataSources.add(jsonUnescape(mVals.group(1)));
        }

        // scope: { ... } then check which key exists
        Matcher mScope = Pattern.compile("\"scope\"\\s*:\\s*\\{(.*?)}", Pattern.DOTALL).matcher(src);
        if (mScope.find()) {
            String inner = mScope.group(1);
            if (inner.contains("\"custom\"")) {
                cfg.scopeType = "custom";
                Matcher mCustomArr = Pattern.compile("\"custom\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL).matcher(inner);
                if (mCustomArr.find()) {
                    String arr = mCustomArr.group(1);
                    Matcher mVals = Pattern.compile("\"(.*?)\"", Pattern.DOTALL).matcher(arr);
                    while (mVals.find()) cfg.scopeRegexes.add(jsonUnescape(mVals.group(1)));
                }
            } else if (inner.contains("\"burp\"")) {
                cfg.scopeType = "burp";
            } else {
                cfg.scopeType = "all";
            }
        }

        // sinks: look for "files":"..." and/or "openSearch":"..."
        Matcher mFiles = Pattern.compile("\"files\"\\s*:\\s*\"(.*?)\"", Pattern.DOTALL).matcher(src);
        if (mFiles.find()) cfg.filesPath = jsonUnescape(mFiles.group(1));

        Matcher mOs = Pattern.compile("\"openSearch\"\\s*:\\s*\"(.*?)\"", Pattern.DOTALL).matcher(src);
        if (mOs.find()) cfg.openSearchUrl = jsonUnescape(mOs.group(1));

        return cfg;
    }

    /** Minimal JSON unescape counterpart to jsonEscape (quotes, backslashes, controls, Unicode escapes). */
    private static String jsonUnescape(String s) {
        if (s == null || s.indexOf('\\') < 0) return s;
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                switch (n) {
                    case '\"': out.append('\"'); break;
                    case '\\': out.append('\\'); break;
                    case '/':  out.append('/');  break;
                    case 'b':  out.append('\b'); break;
                    case 'f':  out.append('\f'); break;
                    case 'n':  out.append('\n'); break;
                    case 'r':  out.append('\r'); break;
                    case 't':  out.append('\t'); break;
                    case 'u':
                        if (i + 4 < s.length()) {
                            String hex = s.substring(i + 1, i + 5);
                            try { out.append((char) Integer.parseInt(hex, 16)); i += 4; }
                            catch (NumberFormatException nfe) { out.append("\\u").append(hex); i += 4; }
                        } else {
                            out.append("\\u");
                        }
                        break;
                    default: out.append(n);
                }
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
