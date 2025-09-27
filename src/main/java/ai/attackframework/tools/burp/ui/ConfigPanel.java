package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.ui.primitives.AutoSizingTextField;
import ai.attackframework.tools.burp.ui.primitives.StatusPanel;
import ai.attackframework.tools.burp.ui.primitives.TextFieldUndo;
import ai.attackframework.tools.burp.ui.primitives.ThickSeparator;
import ai.attackframework.tools.burp.ui.text.Doc;
import net.miginfocom.swing.MigLayout;

import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Main configuration panel for data sources, scope, sinks, and admin actions.
 *
 * <p><strong>EDT:</strong> All UI construction and updates occur on the EDT.</p>
 */
public class ConfigPanel extends JPanel implements ConfigController.Ui {

    @Serial
    private static final long serialVersionUID = 1L;

    // Layout & status sizing
    private static final int INDENT = 30;
    private static final int ROW_GAP = 15;
    private static final int STATUS_MIN_COLS = 20;
    private static final int STATUS_MAX_COLS = 200;
    private static final int ADMIN_HIDE_DELAY_MS = 3000;

    // MigLayout snippets
    private static final String MIG_STATUS_INSETS = "insets 5, novisualpadding";
    private static final String MIG_PREF_COL = "[pref!]";
    private static final String MIG_INSETS0_WRAP1 = "insets 0, wrap 1";
    private static final String MIG_GROWX_WRAP = "growx, wrap";
    private static final String GAPLEFT = "gapleft ";

    // Sources
    private final JCheckBox settingsCheckbox = new JCheckBox("Settings", true);
    private final JCheckBox sitemapCheckbox  = new JCheckBox("Sitemap",  true);
    private final JCheckBox issuesCheckbox   = new JCheckBox("Issues",   true);
    private final JCheckBox trafficCheckbox  = new JCheckBox("Traffic",  true);

    // Scope radios
    private final JRadioButton allRadio       = new JRadioButton("All");
    private final JRadioButton burpSuiteRadio = new JRadioButton("Burp Suite's", true);

    // Custom scope grid (single-grid, 4 columns internally)
    private final ScopeGridPanel scopeGrid = new ScopeGridPanel(
            List.of(new ScopeGridPanel.ScopeEntryInit("^.*acme\\.com$", true))
    );

    // Sinks
    private final JCheckBox fileSinkCheckbox = new JCheckBox("Files", true);
    private final JTextField filePathField   = new AutoSizingTextField("/path/to/directory");
    private final JButton    createFilesButton = new JButton("Create Files");
    private final JTextArea  fileStatus = new JTextArea();
    private final JPanel     fileStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

    private final JCheckBox openSearchSinkCheckbox = new JCheckBox("OpenSearch", false);
    private final JTextField openSearchUrlField    = new AutoSizingTextField("http://opensearch.url:9200");
    private final JButton    testConnectionButton  = new JButton("Test Connection");
    private final JButton    createIndexesButton   = new JButton("Create Indexes");
    private final JTextArea  openSearchStatus      = new JTextArea();
    private final JPanel     openSearchStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

    // Admin status
    private final JTextArea adminStatus = new JTextArea();
    private final JPanel    adminStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));
    private transient Timer adminStatusHideTimer;

    /** Action controller (transient; rebuilt on deserialization). */
    private transient ConfigController controller = new ConfigController(this);

    /** Public no-arg constructor (EDT). */
    public ConfigPanel() { this(null); }

    /**
     * Optional DI constructor for tests.
     * @param injectedController controller to use; when {@code null}, a default is created
     */
    public ConfigPanel(ConfigController injectedController) {
        if (injectedController != null) this.controller = injectedController;

        setLayout(new MigLayout("fillx, insets 12", "[fill]"));

        add(new ConfigSourcesPanel(settingsCheckbox, sitemapCheckbox, issuesCheckbox, trafficCheckbox, INDENT).build(),
                "gaptop 5, gapbottom 5, wrap");
        add(panelSeparator(), MIG_GROWX_WRAP);

        add(buildScopePanel(), "gaptop 10, gapbottom 5, wrap");
        add(panelSeparator(), MIG_GROWX_WRAP);

        JTextArea importExportStatus = new JTextArea();
        JPanel importExportStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

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
                openSearchStatusWrapper,
                INDENT,
                ROW_GAP,
                StatusPanel::configureTextArea
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
                StatusPanel::configureTextArea,
                this::importConfig,
                this::exportConfig,
                new AdminSaveButtonListener()
        ).build(), MIG_GROWX_WRAP);
        add(Box.createVerticalGlue(), "growy, wrap");

        assignComponentNames();
        wireTextFieldEnhancements();
        refreshEnabledStates();
    }

    /** Builds the single-column Scope section: Burp → Custom(+rows) → All. */
    private JPanel buildScopePanel() {
        JPanel panel = new JPanel(new MigLayout(MIG_INSETS0_WRAP1, "[left]"));
        panel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel header = new JLabel("Scope");
        header.setFont(header.getFont().deriveFont(java.awt.Font.BOLD, 18f));
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

    private JComponent panelSeparator() { return new ThickSeparator(); }

    /** {@inheritDoc} */
    @Override public void onFileStatus(String message) {
        StatusPanel.setStatus(fileStatus, fileStatusWrapper, message, STATUS_MIN_COLS, STATUS_MAX_COLS);
    }

    /** {@inheritDoc} */
    @Override public void onOpenSearchStatus(String message) {
        StatusPanel.setStatus(openSearchStatus, openSearchStatusWrapper, message, STATUS_MIN_COLS, STATUS_MAX_COLS);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Off-EDT calls are applied synchronously via {@code invokeAndWait}; the status autohides
     * after {@value #ADMIN_HIDE_DELAY_MS} ms.</p>
     */
    @Override public void onAdminStatus(String message) {
        Runnable r = () -> {
            StatusPanel.setStatus(adminStatus, adminStatusWrapper, message, STATUS_MIN_COLS, STATUS_MAX_COLS);
            if (adminStatusHideTimer != null && adminStatusHideTimer.isRunning()) adminStatusHideTimer.stop();
            adminStatusHideTimer = new Timer(ADMIN_HIDE_DELAY_MS, evt -> {
                adminStatusWrapper.setVisible(false);
                adminStatusWrapper.revalidate();
                adminStatusWrapper.repaint();
            });
            adminStatusHideTimer.setRepeats(false);
            adminStatusHideTimer.start();
        };
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            try {
                javax.swing.SwingUtilities.invokeAndWait(r);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                javax.swing.SwingUtilities.invokeLater(r);
            } catch (Exception ex) {
                javax.swing.SwingUtilities.invokeLater(r);
            }
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p><strong>EDT:</strong> Must be invoked on the EDT.</p>
     */
    @Override public void onImportResult(ConfigState.State state) {
        Runnable r = () -> {
            settingsCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_SETTINGS));
            sitemapCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_SITEMAP));
            issuesCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_FINDINGS));
            trafficCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_TRAFFIC));

            switch (state.scopeType()) {
                case ConfigKeys.SCOPE_CUSTOM -> {
                    // IMPORTANT: build rows first, then flip the radio so enable/disable runs on final state
                    if (!state.customEntries().isEmpty()) {
                        List<ScopeGridPanel.ScopeEntryInit> init = new ArrayList<>(state.customEntries().size());
                        for (ConfigState.ScopeEntry ce : state.customEntries()) {
                            boolean isRegex = ce.kind() == ConfigState.Kind.REGEX;
                            init.add(new ScopeGridPanel.ScopeEntryInit(ce.value(), isRegex));
                        }
                        scopeGrid.setEntries(init);
                    } else {
                        scopeGrid.setEntries(List.of(new ScopeGridPanel.ScopeEntryInit("", true)));
                    }
                    scopeGrid.customRadio().setSelected(true);
                }
                case ConfigKeys.SCOPE_BURP -> burpSuiteRadio.setSelected(true);
                default -> allRadio.setSelected(true);
            }

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
        };
        runOnEdt(r);
    }

    /** Hooks enable/disable behaviors and content-change re-layouts. */
    private void wireButtonActions() {
        fileSinkCheckbox.addItemListener(e -> refreshEnabledStates());
        openSearchSinkCheckbox.addItemListener(e -> refreshEnabledStates());

        createFilesButton.addActionListener(e -> {
            String root = filePathField.getText().trim();
            if (root.isEmpty()) { onFileStatus("✖ Path required"); return; }
            controller.createFilesAsync(root, getSelectedSources());
        });

        testConnectionButton.addActionListener(e -> {
            String url = openSearchUrlField.getText().trim();
            if (url.isEmpty()) { onOpenSearchStatus("✖ URL required"); return; }
            controller.testConnectionAsync(url);
        });

        createIndexesButton.addActionListener(e -> {
            String url = openSearchUrlField.getText().trim();
            if (url.isEmpty()) { onOpenSearchStatus("✖ URL required"); return; }
            controller.createIndexesAsync(url, getSelectedSources());
        });

        DocumentListener relayout = Doc.onChange(() -> {
            filePathField.revalidate();
            openSearchUrlField.revalidate();
        });
        filePathField.getDocument().addDocumentListener(relayout);
        openSearchUrlField.getDocument().addDocumentListener(relayout);
    }

    /** Enables/disables sink text fields and action buttons according to the checkboxes. */
    private void refreshEnabledStates() {
        boolean files = fileSinkCheckbox.isSelected();
        filePathField.setEnabled(files);
        createFilesButton.setEnabled(files);

        boolean os = openSearchSinkCheckbox.isSelected();
        openSearchUrlField.setEnabled(os);
        testConnectionButton.setEnabled(os);
        createIndexesButton.setEnabled(os);
    }

    /** Collects selected source keys for the current panel state. */
    private List<String> getSelectedSources() {
        List<String> selected = new ArrayList<>();
        if (settingsCheckbox.isSelected()) selected.add(ConfigKeys.SRC_SETTINGS);
        if (sitemapCheckbox.isSelected())  selected.add(ConfigKeys.SRC_SITEMAP);
        if (issuesCheckbox.isSelected())   selected.add(ConfigKeys.SRC_FINDINGS);
        if (trafficCheckbox.isSelected())  selected.add(ConfigKeys.SRC_TRAFFIC);
        return selected;
    }

    /** Installs undo/redo and Enter bindings for the two text fields. */
    private void wireTextFieldEnhancements() {
        TextFieldUndo.install(filePathField);
        TextFieldUndo.install(openSearchUrlField);
        filePathField.addActionListener(e -> createFilesButton.doClick());
        openSearchUrlField.addActionListener(e -> testConnectionButton.doClick());
    }

    /** Composes the typed configuration from the current UI state. */
    private ConfigState.State buildCurrentState() {
        List<String> selectedSources = getSelectedSources();

        String scopeType;
        List<ConfigState.ScopeEntry> custom = new ArrayList<>();
        if (allRadio.isSelected()) {
            scopeType = ConfigKeys.SCOPE_ALL;
        } else if (burpSuiteRadio.isSelected()) {
            scopeType = ConfigKeys.SCOPE_BURP;
        } else if (scopeGrid.customRadio().isSelected()) {
            scopeType = ConfigKeys.SCOPE_CUSTOM;
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
            scopeType = ConfigKeys.SCOPE_ALL;
        }

        boolean filesEnabled = fileSinkCheckbox.isSelected();
        boolean osEnabled    = openSearchSinkCheckbox.isSelected();
        String  osUrl        = openSearchUrlField.getText();
        String  filesRoot    = filePathField.getText();

        return new ConfigState.State(
                selectedSources,
                scopeType,
                custom,
                new ConfigState.Sinks(filesEnabled, filesRoot, osEnabled, osUrl)
        );
    }

    /** Exports JSON to a chosen path. */
    private void exportConfig() {
        String json = ConfigJsonMapper.build(buildCurrentState());
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        chooser.setSelectedFile(new File("attackframework-burp-exporter-config.json"));
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) { onAdminStatus("Export cancelled."); return; }
        Path out = ai.attackframework.tools.burp.utils.FileUtil
                .ensureJsonExtension(chooser.getSelectedFile()).toPath();
        controller.exportConfigAsync(out, json);
    }

    /** Imports JSON from a chosen path. */
    private void importConfig() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) { onAdminStatus("Export cancelled."); return; }
        controller.importConfigAsync(chooser.getSelectedFile().toPath());
    }

    /** Assigns stable component names used by headless tests. */
    private void assignComponentNames() {
        settingsCheckbox.setName("src.settings");
        sitemapCheckbox.setName("src.sitemap");
        issuesCheckbox.setName("src.issues");
        trafficCheckbox.setName("src.traffic");

        allRadio.setName("scope.all");
        burpSuiteRadio.setName("scope.burp");
        // Custom radio + fields are named inside ScopeGridPanel

        fileSinkCheckbox.setName("files.enable");
        filePathField.setName("files.path");
        createFilesButton.setName("files.create");

        openSearchSinkCheckbox.setName("os.enable");
        openSearchUrlField.setName("os.url");
        testConnectionButton.setName("os.test");
        createIndexesButton.setName("os.createIndexes");

        adminStatusWrapper.setName("admin.statusWrapper");
        adminStatus.setName("admin.status");
    }

    /** Save button action: delegates to the controller. */
    private class AdminSaveButtonListener implements ActionListener {
        @Override public void actionPerformed(ActionEvent e) {
            controller.saveAsync(buildCurrentState());
        }
    }

    /** Runs a task on the EDT (immediately if already on it). */
    private void runOnEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    /**
     * Restores transient collaborators after deserialization.
     *
     * @param in input stream
     */
    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        this.controller = new ConfigController(this);
    }
}
