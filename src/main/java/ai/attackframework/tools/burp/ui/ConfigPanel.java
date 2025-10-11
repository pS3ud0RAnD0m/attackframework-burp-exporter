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
 * <p><strong>Responsibilities</strong>: renders controls; composes/reads {@link ConfigState.State};
 * delegates long-running operations to {@link ConfigController}.</p>
 *
 * <p><strong>Threading</strong>: all construction and UI updates occur on the EDT.
 * Controller callbacks may arrive off-EDT; those are marshaled back to the EDT.</p>
 *
 * <p><strong>Tests</strong>: component names are stable and used by headless tests.
 * Do not change the {@code setName(...)} values without updating tests.</p>
 */
public class ConfigPanel extends JPanel implements ConfigController.Ui {

    @Serial
    private static final long serialVersionUID = 1L;

    // ----- Layout & status sizing -----

    /** Left indent for scope rows. */
    private static final int INDENT = 30;
    /** Vertical gap between major rows. */
    private static final int ROW_GAP = 15;
    /** Minimum columns for status text areas. */
    private static final int STATUS_MIN_COLS = 20;
    /** Maximum columns for status text areas (prevents runaway growth). */
    private static final int STATUS_MAX_COLS = 200;
    /** Milliseconds to keep admin status visible before auto-hide. */
    private static final int ADMIN_HIDE_DELAY_MS = 3000;

    // ----- MigLayout snippets (centralized to keep constraints consistent) -----

    private static final String MIG_STATUS_INSETS = "insets 5, novisualpadding";
    private static final String MIG_PREF_COL = "[pref!]";
    private static final String MIG_INSETS0_WRAP1 = "insets 0, wrap 1";
    private static final String MIG_GROWX_WRAP = "growx, wrap";
    private static final String GAPLEFT = "gapleft ";

    // ----- Sources (checkboxes reflect selected data sources) -----

    private final JCheckBox settingsCheckbox = new JCheckBox("Settings", true);
    private final JCheckBox sitemapCheckbox  = new JCheckBox("Sitemap",  true);
    private final JCheckBox issuesCheckbox   = new JCheckBox("Issues",   true);
    private final JCheckBox trafficCheckbox  = new JCheckBox("Traffic",  true);

    // ----- Scope (All / Burp / Custom) -----

    private final JRadioButton allRadio       = new JRadioButton("All");
    private final JRadioButton burpSuiteRadio = new JRadioButton("Burp Suite's", true);

    /** Single grid containing all custom rows (radio, field, regex toggle+indicator, add/delete). */
    private final ScopeGridPanel scopeGrid = new ScopeGridPanel(
            List.of(new ScopeGridPanel.ScopeEntryInit("^.*acme\\.com$", true)),
            INDENT
    );

    // ----- Sinks (Files, OpenSearch) -----

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

    // ----- Admin area -----

    private final JTextArea adminStatus = new JTextArea();
    private final JPanel    adminStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));
    private transient Timer adminStatusHideTimer;

    /** Action controller (transient; rebuilt on deserialization). */
    private transient ConfigController controller = new ConfigController(this);

    /** Public no-arg constructor (EDT). */
    public ConfigPanel() { this(null); }

    /**
     * Dependency-injected constructor used by tests.
     *
     * @param injectedController controller to use; when {@code null}, a default is created
     */
    public ConfigPanel(ConfigController injectedController) {
        if (injectedController != null) this.controller = injectedController;

        setLayout(new MigLayout("fillx, insets 12", "[fill]"));

        // Sources
        add(new ConfigSourcesPanel(settingsCheckbox, sitemapCheckbox, issuesCheckbox, trafficCheckbox, INDENT).build(),
                "gaptop 5, gapbottom 5, wrap");
        add(panelSeparator(), MIG_GROWX_WRAP);

        // Scope
        add(buildScopePanel(), "gaptop 10, gapbottom 5, wrap");
        add(panelSeparator(), MIG_GROWX_WRAP);

        // Sinks
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

        // Admin
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

        assignComponentNames();      // stable IDs for headless tests
        wireTextFieldEnhancements(); // undo/redo + Enter bindings
        refreshEnabledStates();      // initial enablement
    }

    /**
     * Builds the single-column Scope section: header → Burp → Custom grid → All.
     *
     * <p>The three radios are grouped; Custom’s radio lives inside {@link #scopeGrid} and is
     * registered here so enable/disable logic is consistent.</p>
     *
     * @return a panel that is added into the main layout
     */
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
        panel.add(scopeGrid.component(), "growx");
        panel.add(allRadio, GAPLEFT + INDENT);

        return panel;
    }

    /** Thin separator component used between sections for readability. */
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
     * <p>Calls may originate off-EDT; this method marshals to the EDT and auto-hides the
     * admin status after {@value #ADMIN_HIDE_DELAY_MS} ms.</p>
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
     * <p><strong>EDT</strong>: marshaled to the EDT. Order matters: for custom scope we
     * first build rows, then select the Custom radio so enable/disable runs on the final state.</p>
     */
    @Override public void onImportResult(ConfigState.State state) {
        Runnable r = () -> {
            settingsCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_SETTINGS));
            sitemapCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_SITEMAP));
            issuesCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_FINDINGS));
            trafficCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_TRAFFIC));

            switch (state.scopeType()) {
                case ConfigKeys.SCOPE_CUSTOM -> {
                    // Build rows first; then flip radio for correct enable/disable
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

    /**
     * Wires button actions and lightweight relayout listeners.
     *
     * <p>Validation is performed inline (e.g., blank path/URL) and status is updated via
     * the {@link StatusPanel} helpers; long-running work is delegated to the controller.</p>
     */
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

        // Relayout on text changes so AutoSizingTextField can update preferred sizes
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

    /**
     * Collects selected source keys for the current panel state.
     *
     * @return ordered list of selected source identifiers (ConfigKeys.SRC_*)
     */
    private List<String> getSelectedSources() {
        List<String> selected = new ArrayList<>();
        if (settingsCheckbox.isSelected()) selected.add(ConfigKeys.SRC_SETTINGS);
        if (sitemapCheckbox.isSelected())  selected.add(ConfigKeys.SRC_SITEMAP);
        if (issuesCheckbox.isSelected())   selected.add(ConfigKeys.SRC_FINDINGS);
        if (trafficCheckbox.isSelected())  selected.add(ConfigKeys.SRC_TRAFFIC);
        return selected;
    }

    /**
     * Installs undo/redo and Enter bindings for the two text fields.
     *
     * <p>Enter triggers the corresponding primary action, matching user expectations.</p>
     */
    private void wireTextFieldEnhancements() {
        TextFieldUndo.install(filePathField);
        TextFieldUndo.install(openSearchUrlField);
        filePathField.addActionListener(e -> createFilesButton.doClick());
        openSearchUrlField.addActionListener(e -> testConnectionButton.doClick());
    }

    /**
     * Composes the typed configuration from the current UI state.
     *
     * @return immutable state object suitable for serialization/export
     */
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
                if (v == null || v.trim().isEmpty()) continue; // omit blanks
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

    /**
     * Exports JSON to a chosen path.
     *
     * <p>Shows a chooser; on approval delegates writing to {@link ConfigController} to keep I/O off the EDT.</p>
     */
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

    /**
     * Imports JSON from a chosen path.
     *
     * <p>Shows a chooser; on approval hands the path to {@link ConfigController} for parsing off the EDT.</p>
     */
    private void importConfig() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) { onAdminStatus("Export cancelled."); return; }
        controller.importConfigAsync(chooser.getSelectedFile().toPath());
    }

    /**
     * Assigns stable component names used by headless tests.
     *
     * <p>These names are part of the test contract. Keep synchronized with tests if changed.</p>
     */
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
        createFilesButton.setToolTipText("Create OpenSearch index files");

        openSearchSinkCheckbox.setName("os.enable");
        openSearchUrlField.setName("os.url");
        testConnectionButton.setName("os.test");
        testConnectionButton.setToolTipText("Test connection to OpenSearch");
        createIndexesButton.setName("os.createIndexes");
        createIndexesButton.setToolTipText("Create indexes for OpenSearch\nNote: This is not required because indexes will auto-create if needed. However, this button is helpful for confirming permissions.");

        adminStatusWrapper.setName("admin.statusWrapper");
        adminStatus.setName("admin.status");
    }

    /** Save button action: delegates to the controller (synchronous logging + UI status). */
    private class AdminSaveButtonListener implements ActionListener {
        @Override public void actionPerformed(ActionEvent e) {
            controller.saveAsync(buildCurrentState());
        }
    }

    /**
     * Runs a task on the EDT (immediately if already on it).
     *
     * @param r runnable to execute on the EDT
     */
    private void runOnEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    /**
     * Restores transient collaborators after deserialization.
     *
     * @param in input stream
     * @throws IOException if deserialization fails
     * @throws ClassNotFoundException if a class cannot be resolved
     */
    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        this.controller = new ConfigController(this);
    }
}
