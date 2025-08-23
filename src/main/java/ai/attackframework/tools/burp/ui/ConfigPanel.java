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
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * UI for selecting sources/scope, configuring sinks, running actions,
 * and surfacing status.
 */
public class ConfigPanel extends JPanel {

    // Layout & status sizing
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
    private final JRadioButton customRadio    = new JRadioButton("Custom");
    private final JTextField   customScopeField = new AutoSizingTextField("^.*acme\\.com$");

    // Custom scope inputs live on a single row for compactness
    private final JCheckBox customScopeRegexToggle = new JCheckBox(".*"); // unchecked = string match
    final JButton addCustomScopeButton = new JButton("Add");
    // Container uses explicit columns so fields/buttons align
    private final JPanel customScopesContainer = new JPanel(
            new MigLayout("insets 0, wrap 1", "[left][grow,fill][left][left][left]")
    );
    final List<JTextField> customScopeFields = new ArrayList<>();
    private final List<JCheckBox> customScopeRegexToggles = new ArrayList<>();
    private final List<JLabel> customScopeIndicators = new ArrayList<>();

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

    // Admin status
    private final JTextArea adminStatus = new JTextArea();
    private final JPanel    adminStatusWrapper = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));
    private Timer adminStatusHideTimer;

    private final JTextArea importExportStatus = new JTextArea();
    private final JPanel    importExportStatusWrapper = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));

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

        assignComponentNames();
        wireTextFieldEnhancements();
        refreshEnabledStates();
    }

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

        // First row: radio + field + toggle + indicator + Add button
        JLabel firstIndicator = new JLabel();
        firstIndicator.setName("scope.custom.regex.indicator.1");

        customScopesContainer.removeAll();
        customScopesContainer.add(customRadio,           "cell 0 0");
        customScopesContainer.add(customScopeField,      "cell 1 0, growx");
        customScopesContainer.add(customScopeRegexToggle,"cell 2 0");
        customScopesContainer.add(firstIndicator,        "cell 3 0");
        customScopesContainer.add(addCustomScopeButton,  "cell 4 0");

        if (customScopeFields.isEmpty()) {
            customScopeFields.add(customScopeField);
            customScopeRegexToggles.add(customScopeRegexToggle);
            customScopeIndicators.add(firstIndicator);
        }

        panel.add(customScopesContainer, "gapleft " + INDENT + ", growx");

        // Wiring for the first field
        customScopeRegexToggle.addActionListener(e -> updateCustomRegexFeedback());
        customScopeField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { updateCustomRegexFeedback(); customScopeField.revalidate(); }
            public void removeUpdate(DocumentEvent e) { updateCustomRegexFeedback(); customScopeField.revalidate(); }
            public void changedUpdate(DocumentEvent e) { updateCustomRegexFeedback(); customScopeField.revalidate(); }
        });

        addCustomScopeButton.addActionListener(e -> addCustomScopeFieldRow());

        panel.add(allRadio, "gapleft " + INDENT);

        return panel;
    }

    /** Adds another custom scope field (stacked vertically under the first). */
    private void addCustomScopeFieldRow() {
        if (customScopeFields.size() >= 100) {
            addCustomScopeButton.setEnabled(false);
            return;
        }

        JTextField field = new AutoSizingTextField("");
        JCheckBox toggle = new JCheckBox(".*");
        toggle.setToolTipText("Regex (off = string match)");
        JLabel indicator = new JLabel();
        JButton deleteBtn = new JButton("Delete");

        int rowIndex = customScopeFields.size(); // next available row index (0 already used by default)
        int idx = rowIndex + 1;

        field.setName("scope.custom.regex." + idx);
        toggle.setName("scope.custom.regex.toggle." + idx);
        indicator.setName("scope.custom.regex.indicator." + idx);
        deleteBtn.setName("scope.custom.regex.delete." + idx);
        deleteBtn.setToolTipText("Remove this filter");

        // Add directly into the shared container by row
        customScopesContainer.add(field,     "cell 1 " + rowIndex + ", growx");
        customScopesContainer.add(toggle,    "cell 2 " + rowIndex);
        customScopesContainer.add(indicator, "cell 3 " + rowIndex);
        customScopesContainer.add(deleteBtn, "cell 4 " + rowIndex);

        customScopeFields.add(field);
        customScopeRegexToggles.add(toggle);
        customScopeIndicators.add(indicator);

        // Undo/redo + wiring
        installUndoRedo(field);
        toggle.addActionListener(e -> updateCustomRegexFeedback());
        field.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { updateCustomRegexFeedback(); field.revalidate(); }
            public void removeUpdate(DocumentEvent e) { updateCustomRegexFeedback(); field.revalidate(); }
            public void changedUpdate(DocumentEvent e) { updateCustomRegexFeedback(); field.revalidate(); }
        });

        deleteBtn.addActionListener(e -> removeCustomScopeFieldRow(field));

        if (customScopeFields.size() >= 100) {
            addCustomScopeButton.setEnabled(false);
        }

        customScopesContainer.revalidate();
        customScopesContainer.repaint();
    }

    /** Removes a specific custom scope field row and rebuilds the layout. */
    void removeCustomScopeFieldRow(JTextField field) {
        int i = customScopeFields.indexOf(field);
        if (i <= 0) return; // do not remove the first field

        customScopeFields.remove(i);
        customScopeRegexToggles.remove(i);
        customScopeIndicators.remove(i);

        rebuildCustomScopeRows();
        addCustomScopeButton.setEnabled(true);
    }

    /** Rebuilds all custom scope rows to keep MigLayout indices consistent. */
    private void rebuildCustomScopeRows() {
        customScopesContainer.removeAll();

        // First row: radio + first field + toggle + indicator + Add button
        JTextField firstField = customScopeFields.getFirst();
        JCheckBox firstToggle = customScopeRegexToggles.getFirst();
        JLabel firstIndicator = customScopeIndicators.getFirst();

        JPanel firstRow = new JPanel(new MigLayout("insets 0, flowx", "", ""));
        firstRow.add(customRadio);
        firstRow.add(firstField, "gapleft 20");
        firstRow.add(firstToggle, "gapleft 3");
        firstRow.add(firstIndicator, "gapleft 3");
        firstRow.add(addCustomScopeButton, "gapleft 20");
        customScopesContainer.add(firstRow, "growx, wrap");

        // Subsequent rows: field + toggle + indicator + delete
        for (int j = 1; j < customScopeFields.size(); j++) {
            JTextField field = customScopeFields.get(j);
            JCheckBox toggle = customScopeRegexToggles.get(j);
            JLabel indicator = customScopeIndicators.get(j);
            JButton deleteBtn = new JButton("Delete");
            deleteBtn.setName("scope.custom.regex.delete." + (j + 1));

            JPanel row = new JPanel(new MigLayout("insets 0, flowx", "", ""));
            row.add(field, "gapleft 53");
            row.add(toggle, "gapleft 3");
            row.add(indicator, "gapleft 3");
            row.add(deleteBtn, "gapleft 5");

            deleteBtn.addActionListener(e -> removeCustomScopeFieldRow(field));
            customScopesContainer.add(row, "growx, wrap");
        }

        customScopesContainer.revalidate();
        customScopesContainer.repaint();
    }

    /** Updates ✓/✖ indicators; shows nothing when the regex toggle is off or the field is blank. */
    private void updateCustomRegexFeedback() {
        for (int i = 0; i < customScopeFields.size(); i++) {
            JTextField field = customScopeFields.get(i);
            JLabel indicator = customScopeIndicators.get(i);
            boolean regexOn = i < customScopeRegexToggles.size() && customScopeRegexToggles.get(i).isSelected();

            String text = field.getText();
            if (!regexOn || text == null || text.isBlank()) {
                indicator.setVisible(false);
                indicator.setText("");
                indicator.setToolTipText(null);
                continue;
            }

            try {
                Pattern.compile(text);
                indicator.setForeground(new Color(0, 153, 0));
                indicator.setText("✓");
                indicator.setToolTipText("Valid regex");
            } catch (PatternSyntaxException ex) {
                indicator.setForeground(new Color(200, 0, 0));
                indicator.setText("✖");
                indicator.setToolTipText(ex.getDescription());
            }
            indicator.setVisible(true);
        }
    }

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

        // Keep fields sized to content while typing.
        DocumentListener relayout = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
            public void removeUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
            public void changedUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
        };
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

    // Auto-sizing text field
    private static class AutoSizingTextField extends JTextField {
        public AutoSizingTextField(String text) { super(text); }
        @Override public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            int textWidth = fm.stringWidth(getText()) + 20;
            int height = super.getPreferredSize().height;
            int w = Math.max(80, Math.min(900, textWidth));
            return new Dimension(w, height);
        }
    }

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

    private String currentConfigJson() {
        List<String> selectedSources = getSelectedSources();

        String scopeType;
        List<String> scopeValues = null;
        List<String> scopeKinds = null;
        if (allRadio.isSelected()) {
            scopeType = "all";
        } else if (burpSuiteRadio.isSelected()) {
            scopeType = "burp";
        } else {
            scopeType = "custom";
            scopeValues = new ArrayList<>();
            scopeKinds = new ArrayList<>();
            for (int i = 0; i < customScopeFields.size(); i++) {
                JTextField f = customScopeFields.get(i);
                String v = f.getText();
                if (v != null && !v.trim().isEmpty()) {
                    scopeValues.add(v.trim());
                    boolean regexOn = i < customScopeRegexToggles.size() && customScopeRegexToggles.get(i).isSelected();
                    scopeKinds.add(regexOn ? "regex" : "string");
                }
            }
        }

        boolean filesEnabled = fileSinkCheckbox.isSelected();
        boolean osEnabled    = openSearchSinkCheckbox.isSelected();
        String  osUrl        = openSearchUrlField.getText();
        String  filesRoot    = filePathField.getText();

        return Json.buildConfigJsonTyped(
                selectedSources, scopeType, scopeValues, scopeKinds,
                filesEnabled, filesRoot, osEnabled, osUrl
        );
    }

    // Import / Export

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
            updateCustomRegexFeedback(); // reflect imported values in indicators
            updateImportExportStatus("Imported from " + file.getAbsolutePath());
            Logger.logInfo("Config imported from " + file.getAbsolutePath());

            if ("custom".equals(cfg.scopeType()) && cfg.scopeRegexes().size() > 1) {
                Logger.logInfo("Imported multiple custom regex entries; using the first. Additional fields will be supported later.");
            }

        } catch (Exception ex) {
            updateImportExportStatus("✖ Import error: " + ex.getMessage());
            Logger.logError("Import error: " + ex.getMessage());
        }
    }

    // chooser-free helpers (package-private for tests)
    void exportConfigTo(Path out) throws IOException {
        FileUtil.writeStringCreateDirs(out, currentConfigJson());
        Logger.logInfo("Config exported to " + out.toAbsolutePath());
    }

    void importConfigFrom(Path in) throws IOException {
        String json = FileUtil.readString(in);
        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        applyImported(cfg);
        refreshEnabledStates();
        updateCustomRegexFeedback();
        Logger.logInfo("Config imported from " + in.toAbsolutePath());
    }

    // apply imported values to the UI
    private void applyImported(Json.ImportedConfig cfg) {
        // Sources
        settingsCheckbox.setSelected(cfg.dataSources().contains("settings"));
        sitemapCheckbox.setSelected(cfg.dataSources().contains("sitemap"));
        issuesCheckbox.setSelected(cfg.dataSources().contains("findings"));
        trafficCheckbox.setSelected(cfg.dataSources().contains("traffic"));

        // Scope (uses first custom entry if multiples are present)
        switch (cfg.scopeType()) {
            case "custom" -> {
                customRadio.setSelected(true);
                customScopeField.setText(cfg.scopeRegexes().isEmpty() ? "" : cfg.scopeRegexes().getFirst());
            }
            case "burp" -> burpSuiteRadio.setSelected(true);
            default -> allRadio.setSelected(true);
        }

        // Sinks
        if (cfg.filesPath() != null) {
            fileSinkCheckbox.setSelected(true);
            filePathField.setText(cfg.filesPath());
        } else {
            fileSinkCheckbox.setSelected(false);
        }
        if (cfg.openSearchUrl() != null) {
            openSearchSinkCheckbox.setSelected(true);
            openSearchUrlField.setText(cfg.openSearchUrl());
        } else {
            openSearchSinkCheckbox.setSelected(false);
        }
    }

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

    // text-input helpers: undo/redo + Enter-to-action
    private void wireTextFieldEnhancements() {
        installUndoRedo(filePathField);
        installUndoRedo(openSearchUrlField);
        installUndoRedo(customScopeField);

        filePathField.addActionListener(e -> createFilesButton.doClick());
        openSearchUrlField.addActionListener(e -> testConnectionButton.doClick());
    }

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

    @Override public void paint(Graphics g) { super.paint(g); }
}
