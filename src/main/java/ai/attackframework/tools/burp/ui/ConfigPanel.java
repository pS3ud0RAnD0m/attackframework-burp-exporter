package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.sinks.OpenSearchSink;
import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.attackframework.tools.burp.ui.text.Doc;
import net.miginfocom.swing.MigLayout;

import javax.swing.AbstractAction;
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
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.undo.UndoManager;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * UI panel for configuring data sources, scope, sinks, and admin actions.
 * Provides buttons for managing sinks, configuring scope fields, and displaying status.
 *
 * <p>All Swing updates are expected on the EDT.</p>
 */
public class ConfigPanel extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    // Layout & status sizing
    private static final int INDENT = 30;
    private static final int ROW_GAP = 15;
    private static final int STATUS_MIN_COLS = 20;
    private static final int STATUS_MAX_COLS = 200;

    // MigLayout snippets
    private static final String MIG_STATUS_INSETS = "insets 5, novisualpadding";
    private static final String MIG_PREF_COL = "[pref!]";
    private static final String MIG_INSETS0_WRAP1 = "insets 0, wrap 1";
    private static final String MIG_GROWX_WRAP = "growx, wrap";
    private static final String GAPLEFT = "gapleft ";

    // Scope type literals
    private static final String SCOPE_ALL = "all";
    private static final String SCOPE_BURP = "burp";
    private static final String SCOPE_CUSTOM = "custom";

    // Error/status prefixes
    private static final String ERR_PREFIX = "✖ Error: ";
    private static final String ERR_FILE_CREATE = "File creation error: ";
    private static final String ERR_INDEX_CREATE = "Index creation error: ";

    // Sources
    private final JCheckBox settingsCheckbox = new JCheckBox("Settings", true);
    private final JCheckBox sitemapCheckbox  = new JCheckBox("Sitemap",  true);
    private final JCheckBox issuesCheckbox   = new JCheckBox("Issues",   true);
    private final JCheckBox trafficCheckbox  = new JCheckBox("Traffic",  true);

    // Scope radios
    private final JRadioButton allRadio       = new JRadioButton("All");
    private final JRadioButton burpSuiteRadio = new JRadioButton("Burp Suite's", true);

    // Scope grid (custom). The grid owns rows/sizing/glyphs.
    private final ScopeGridPanel scopeGrid = new ScopeGridPanel(
            List.of(new ScopeGridPanel.ScopeEntryInit("^.*acme\\.com$", false)),
            INDENT
    );

    // Files sink
    private final JCheckBox fileSinkCheckbox = new JCheckBox("Files", true);
    private final JTextField filePathField   = new AutoSizingTextField("/path/to/directory");
    private final JButton    createFilesButton = new JButton("Create Files");
    private final JTextArea  fileStatus = new JTextArea();
    private final JPanel     fileStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

    // OpenSearch sink
    private final JCheckBox openSearchSinkCheckbox = new JCheckBox("OpenSearch", false);
    private final JTextField openSearchUrlField    = new AutoSizingTextField("http://opensearch.url:9200");
    private final JButton    testConnectionButton  = new JButton("Test Connection");
    private final JButton    createIndexesButton   = new JButton("Create Indexes");
    private final JTextArea  openSearchStatus      = new JTextArea();
    private final JPanel     statusWrapper         = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

    // Admin status
    private final JTextArea adminStatus = new JTextArea();
    private final JPanel    adminStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));
    private Timer adminStatusHideTimer;

    private final JTextArea importExportStatus = new JTextArea();
    private final JPanel    importExportStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

    public ConfigPanel() {
        setLayout(new MigLayout("fillx, insets 12", "[fill]"));

        add(new ConfigSourcesPanel(settingsCheckbox, sitemapCheckbox, issuesCheckbox, trafficCheckbox, INDENT).build(),
                "gaptop 5, gapbottom 5, wrap");
        add(panelSeparator(), MIG_GROWX_WRAP);

        // Scope section:
        // - Uses ScopeGridPanel for custom rows (UI only, no JSON/business logic here).
        // - ButtonGroup owns selection across 'All', 'Burp Suite', and 'Custom'.
        add(buildScopePanel(), "gaptop 10, gapbottom 5, wrap");
        add(panelSeparator(), MIG_GROWX_WRAP);

        // Sinks and Admin
        add(new ConfigSinksPanel(
                fileSinkCheckbox,
                filePathField,
                createFilesButton,
                fileStatus,
                fileStatusWrapper,
                openSearchSinkCheckbox,
                openSearchUrlField,
                testConnectionButton,
                createIndexesButton,
                openSearchStatus,
                statusWrapper,
                INDENT,
                ROW_GAP,
                this::configureTextArea
        ).build(), "gaptop 10, gapbottom 5, wrap");
        wireButtonActions();
        add(panelSeparator(), MIG_GROWX_WRAP);

        add(new ConfigAdminPanel(
                importExportStatus,
                importExportStatusWrapper,
                adminStatus,
                adminStatusWrapper,
                INDENT,
                ROW_GAP,
                this::configureTextArea,
                this::importConfig,
                this::exportConfig,
                new AdminSaveButtonListener()
        ).build(), MIG_GROWX_WRAP);
        add(Box.createVerticalGlue(), "growy, wrap");

        assignComponentNames();
        wireTextFieldEnhancements();
        refreshEnabledStates();
    }

    /** Build the scope section and embed the custom grid. */
    private JPanel buildScopePanel() {
        JPanel panel = new JPanel(new MigLayout(MIG_INSETS0_WRAP1, "[left]"));
        panel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel header = new JLabel("Scope");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(burpSuiteRadio);
        scopeGroup.add(scopeGrid.customRadio());
        scopeGroup.add(allRadio);

        panel.add(burpSuiteRadio, GAPLEFT + INDENT);
        panel.add(scopeGrid.component(), GAPLEFT + INDENT + ", growx");
        panel.add(allRadio, GAPLEFT + INDENT);

        return panel;
    }

    private JComponent panelSeparator() {
        return new JSeparator() {
            @Override public Dimension getPreferredSize() {
                return new Dimension(super.getPreferredSize().width, 2);
            }
            @Override protected void paintComponent(java.awt.Graphics g) {
                super.paintComponent(g);
                g.setColor(getForeground());
                g.fillRect(0, 1, getWidth(), 2);
            }
        };
    }

    private void configureTextArea(JTextArea area) {
        area.setEditable(false);
        area.setLineWrap(false);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setFont(new Font("Monospaced", Font.PLAIN, 12));
        area.setRows(1);
        area.setColumns(1);
    }

    // Status helpers
    private static void setStatus(JTextArea area, JPanel wrapper, String message) {
        area.setText(message);
        String[] lines = message.split("\r\n|\r|\n", -1);
        int rows = Math.max(lines.length, 1);
        int cols = Math.clamp(maxLineLength(lines), STATUS_MIN_COLS, STATUS_MAX_COLS);
        area.setRows(rows);
        area.setColumns(cols);
        wrapper.setVisible(true);
        wrapper.revalidate();
        wrapper.repaint();
    }
    private void updateStatus(String message) { setStatus(openSearchStatus, statusWrapper, message); }
    private void updateFileStatus(String message) { setStatus(fileStatus, fileStatusWrapper, message); }
    private void updateImportExportStatus(String message) { setStatus(importExportStatus, importExportStatusWrapper, message); }

    private static int maxLineLength(String[] lines) {
        int max = 1;
        for (String s : lines) if (s != null && s.length() > max) max = s.length();
        return max;
    }

    // ---- Wiring (reduced complexity into helpers) ----

    private void wireButtonActions() {
        wireSinkEnablement();
        wireCreateFilesAction();
        wireTestConnectionAction();
        wireCreateIndexesAction();
        wireRelayoutDocListeners();
    }

    private void wireSinkEnablement() {
        fileSinkCheckbox.addItemListener(e -> refreshEnabledStates());
        openSearchSinkCheckbox.addItemListener(e -> refreshEnabledStates());
    }

    private void wireCreateFilesAction() {
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
                        updateFileStatus(summarizeFileCreateResults(results));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        updateFileStatus("✖ File creation interrupted");
                        Logger.logError("File creation interrupted: " + ie.getMessage());
                    } catch (ExecutionException ee) {
                        String msg = ee.getCause() != null ? ee.getCause().getMessage() : ee.getMessage();
                        updateFileStatus(ERR_FILE_CREATE + msg);
                        Logger.logError(ERR_FILE_CREATE + ee);
                    } catch (Exception ex) {
                        updateFileStatus(ERR_FILE_CREATE + ex.getMessage());
                        Logger.logError(ERR_FILE_CREATE + ex.getMessage());
                    } finally {
                        createFilesButton.setEnabled(true);
                    }
                }
            }.execute();
        });
    }

    private String summarizeFileCreateResults(List<FileUtil.CreateResult> results) {
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
        return sb.toString().trim();
    }

    private void wireTestConnectionAction() {
        testConnectionButton.addActionListener(e -> onTestConnection());
    }

    /** Extracted to reduce complexity in the action listener body. */
    private void onTestConnection() {
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
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    updateStatus("✖ Connection test interrupted");
                    Logger.logError("OpenSearch connection interrupted: " + ie.getMessage());
                } catch (ExecutionException ee) {
                    String msg = ee.getCause() != null ? String.valueOf(ee.getCause()) : ee.getMessage();
                    updateStatus(ERR_PREFIX + msg);
                    Logger.logError("OpenSearch connection error: " + ee);
                } catch (Exception ex) {
                    updateStatus(ERR_PREFIX + ex.getMessage());
                    Logger.logError("OpenSearch connection error: " + ex.getMessage());
                } finally {
                    testConnectionButton.setEnabled(true);
                }
            }
        }.execute();
    }

    private void wireCreateIndexesAction() {
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
                        updateStatus(summarizeIndexResults(results));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        updateStatus("✖ Index creation interrupted");
                        Logger.logError("Index creation interrupted: " + ie.getMessage());
                    } catch (ExecutionException ee) {
                        String msg = ee.getCause() != null ? ee.getCause().getMessage() : ee.getMessage();
                        updateStatus(ERR_INDEX_CREATE + msg);
                        Logger.logError(ERR_INDEX_CREATE + ee);
                    } catch (Exception ex) {
                        updateStatus(ERR_INDEX_CREATE + ex.getMessage());
                        Logger.logError(ERR_INDEX_CREATE + ex.getMessage());
                    } finally {
                        createIndexesButton.setEnabled(true);
                    }
                }
            }.execute();
        });
    }

    private String summarizeIndexResults(List<IndexResult> results) {
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
        boolean allExist = !results.isEmpty() && results.stream().allMatch(r -> r.status() == IndexResult.Status.EXISTS);

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
        return sb.toString().trim();
    }

    private void wireRelayoutDocListeners() {
        DocumentListener relayout = Doc.onChange(() -> {
            filePathField.revalidate();
            openSearchUrlField.revalidate();
        });
        filePathField.getDocument().addDocumentListener(relayout);
        openSearchUrlField.getDocument().addDocumentListener(relayout);
    }

    /** Disable sink text fields when deselected; leave action buttons enabled. */
    private void refreshEnabledStates() {
        boolean files = fileSinkCheckbox.isSelected();
        filePathField.setEnabled(files);
        createFilesButton.setEnabled(true);

        boolean os = openSearchSinkCheckbox.isSelected();
        openSearchUrlField.setEnabled(os);
    }

    private List<String> getSelectedSources() {
        List<String> selected = new ArrayList<>();
        if (settingsCheckbox.isSelected()) selected.add("settings");
        if (sitemapCheckbox.isSelected())  selected.add("sitemap");
        if (issuesCheckbox.isSelected())   selected.add("findings");
        if (trafficCheckbox.isSelected())  selected.add("traffic");
        return selected;
    }

    private static class AutoSizingTextField extends JTextField {
        public AutoSizingTextField(String text) { super(text); }
        @Override public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            int textWidth = fm.stringWidth(getText()) + 20;
            int height = super.getPreferredSize().height;
            int w = Math.clamp(textWidth, 80, 900);
            return new Dimension(w, height);
        }
    }

    private class AdminSaveButtonListener implements ActionListener {
        @Override public void actionPerformed(ActionEvent e) {
            try {
                String json = currentConfigJson();
                Logger.logInfo("Saving config ...");
                Logger.logInfo(json);

                // Inline status update
                setStatus(adminStatus, adminStatusWrapper, "Saved!");
                if (adminStatusHideTimer != null && adminStatusHideTimer.isRunning()) adminStatusHideTimer.stop();
                adminStatusHideTimer = new Timer(3000, evt -> {
                    adminStatusWrapper.setVisible(false);
                    adminStatusWrapper.revalidate();
                    adminStatusWrapper.repaint();
                });
                adminStatusHideTimer.setRepeats(false);
                adminStatusHideTimer.start();

            } catch (Exception ex) {
                setStatus(adminStatus, adminStatusWrapper, ERR_PREFIX + ex.getMessage());
                Logger.logError("Admin save error: " + ex.getMessage());
            }
        }
    }

    /**
     * Builds the current config JSON via the typed model and mapper.
     * Keeps output shape compatible with the legacy JSON.
     */
    private String currentConfigJson() {
        List<String> selectedSources = getSelectedSources();

        String scopeType;
        List<ConfigState.ScopeEntry> custom = new ArrayList<>();
        if (allRadio.isSelected()) {
            scopeType = SCOPE_ALL;
        } else if (burpSuiteRadio.isSelected()) {
            scopeType = SCOPE_BURP;
        } else if (scopeGrid.customRadio().isSelected()) {
            scopeType = SCOPE_CUSTOM;
            List<String> vals  = scopeGrid.values();
            List<Boolean> kinds = scopeGrid.regexKinds();
            int n = Math.min(vals.size(), kinds.size());
            for (int i = 0; i < n; i++) {
                String v = vals.get(i);
                if (v == null || v.trim().isEmpty()) continue;
                boolean isRegex = Boolean.TRUE.equals(kinds.get(i));
                custom.add(new ConfigState.ScopeEntry(
                        v.trim(), isRegex ? ConfigState.Kind.REGEX : ConfigState.Kind.STRING));
            }
        } else {
            scopeType = SCOPE_ALL; // defensive fallback
        }

        boolean filesEnabled = fileSinkCheckbox.isSelected();
        boolean osEnabled    = openSearchSinkCheckbox.isSelected();
        String  osUrl        = openSearchUrlField.getText();
        String  filesRoot    = filePathField.getText();

        ConfigState.State state = new ConfigState.State(
                selectedSources,
                scopeType,
                custom,
                new ConfigState.Sinks(filesEnabled, filesRoot, osEnabled, osUrl)
        );

        return ConfigJsonMapper.build(state);
    }

    private void exportConfig() {
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
            updateImportExportStatus(ERR_PREFIX + ioe.getMessage());
            Logger.logError("Export error: " + ioe.getMessage());
        }
    }

    private void importConfig() {
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

            // Parse via typed mapper and apply to UI (no reflection, no legacy shims).
            ConfigState.State state = ConfigJsonMapper.parse(json);

            // Data sources
            settingsCheckbox.setSelected(state.dataSources().contains("settings"));
            sitemapCheckbox.setSelected(state.dataSources().contains("sitemap"));
            issuesCheckbox.setSelected(state.dataSources().contains("findings"));
            trafficCheckbox.setSelected(state.dataSources().contains("traffic"));

            // Scope
            switch (state.scopeType()) {
                case SCOPE_CUSTOM -> {
                    scopeGrid.customRadio().setSelected(true);
                    // Back-compat: only set the first value (same UX as before)
                    if (!state.customEntries().isEmpty()) {
                        scopeGrid.setFirstValue(state.customEntries().getFirst().value());
                    } else {
                        scopeGrid.setFirstValue("");
                    }
                }
                case SCOPE_BURP -> burpSuiteRadio.setSelected(true);
                default -> allRadio.setSelected(true);
            }

            // Sinks
            if (state.sinks().filesEnabled() && state.sinks().filesPath() != null) {
                fileSinkCheckbox.setSelected(true);
                filePathField.setText(state.sinks().filesPath());
            } else {
                fileSinkCheckbox.setSelected(false);
            }
            if (state.sinks().osEnabled() && state.sinks().openSearchUrl() != null) {
                openSearchSinkCheckbox.setSelected(true);
                openSearchUrlField.setText(state.sinks().openSearchUrl());
            } else {
                openSearchSinkCheckbox.setSelected(false);
            }

            refreshEnabledStates();
            updateImportExportStatus("Imported from " + file.getAbsolutePath());
            Logger.logInfo("Config imported from " + file.getAbsolutePath());

        } catch (Exception ex) {
            updateImportExportStatus(ERR_PREFIX + ex.getMessage());
            Logger.logError("Import error: " + ex.getMessage());
        }
    }

    private void assignComponentNames() {
        settingsCheckbox.setName("src.settings");
        sitemapCheckbox.setName("src.sitemap");
        issuesCheckbox.setName("src.issues");
        trafficCheckbox.setName("src.traffic");

        allRadio.setName("scope.all");
        burpSuiteRadio.setName("scope.burp");
        // custom radio + custom fields are named inside ScopeGridPanel

        fileSinkCheckbox.setName("files.enable");
        filePathField.setName("files.path");
        createFilesButton.setName("files.create");

        openSearchSinkCheckbox.setName("os.enable");
        openSearchUrlField.setName("os.url");
        testConnectionButton.setName("os.test");
        createIndexesButton.setName("os.createIndexes");
    }

    private void wireTextFieldEnhancements() {
        installUndoRedo(filePathField);
        installUndoRedo(openSearchUrlField);

        filePathField.addActionListener(e -> createFilesButton.doClick());
        openSearchUrlField.addActionListener(e -> testConnectionButton.doClick());
    }

    private static void installUndoRedo(JTextField field) {
        UndoManager undo = new UndoManager();
        undo.setLimit(200);
        field.getDocument().addUndoableEditListener(undo);

        field.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, java.awt.event.InputEvent.CTRL_DOWN_MASK), "undo");
        field.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, java.awt.event.InputEvent.META_DOWN_MASK), "undo");

        field.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_Y, java.awt.event.InputEvent.CTRL_DOWN_MASK), "redo");
        field.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_Y, java.awt.event.InputEvent.META_DOWN_MASK), "redo");
        field.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, java.awt.event.InputEvent.CTRL_DOWN_MASK | java.awt.event.InputEvent.SHIFT_DOWN_MASK), "redo");
        field.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, java.awt.event.InputEvent.META_DOWN_MASK | java.awt.event.InputEvent.SHIFT_DOWN_MASK), "redo");

        field.getActionMap().put("undo", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { if (undo.canUndo()) undo.undo(); }
        });
        field.getActionMap().put("redo", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { if (undo.canRedo()) undo.redo(); }
        });
    }
}
