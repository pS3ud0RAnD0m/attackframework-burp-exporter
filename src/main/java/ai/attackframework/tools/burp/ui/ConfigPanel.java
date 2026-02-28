package ai.attackframework.tools.burp.ui;

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;

import ai.attackframework.tools.burp.sinks.FindingsIndexReporter;
import ai.attackframework.tools.burp.sinks.ProxyHistoryIndexReporter;
import ai.attackframework.tools.burp.sinks.SettingsIndexReporter;
import ai.attackframework.tools.burp.sinks.SitemapIndexReporter;
import ai.attackframework.tools.burp.sinks.ToolIndexConfigReporter;
import ai.attackframework.tools.burp.sinks.ToolIndexStatsReporter;
import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.ui.primitives.AutoSizingTextField;
import ai.attackframework.tools.burp.ui.primitives.ScopeGrid;
import ai.attackframework.tools.burp.ui.primitives.StatusViews;
import ai.attackframework.tools.burp.ui.primitives.TextFieldUndo;
import ai.attackframework.tools.burp.ui.primitives.ThickSeparator;
import ai.attackframework.tools.burp.ui.primitives.TriStateCheckBox;
import ai.attackframework.tools.burp.ui.text.Doc;
import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import net.miginfocom.swing.MigLayout;

/**
 * Main configuration panel for data sources, scope, sinks, and control actions.
 *
 * <p><strong>Responsibilities:</strong> render the UI, compose/parse {@link ConfigState.State},
 * and delegate long-running work to {@link ConfigController}.</p>
 *
 * <p><strong>Threading:</strong> callers construct and interact with this panel on the EDT.</p>
 */
public class ConfigPanel extends JPanel implements ConfigController.Ui {

    @Serial private static final long serialVersionUID = 1L;

    // ---- Layout & status sizing
    private static final int INDENT = 30;
    private static final int ROW_GAP = 15;
    private static final String MIG_STATUS_INSETS = "insets 5, novisualpadding";
    private static final String MIG_PREF_COL = "[pref!]";
    private static final String MIG_FILL_WRAP = "growx, wrap";
    private static final int STATUS_MIN_COLS = 20;
    private static final int STATUS_MAX_COLS = 200;
    private static final int CONTROL_HIDE_DELAY_MS = 3000;

    // ---- Sources
    private final TriStateCheckBox settingsCheckbox = new TriStateCheckBox("Settings", TriStateCheckBox.State.SELECTED);
    private final JCheckBox sitemapCheckbox  = new JCheckBox("Sitemap",  true);
    private final TriStateCheckBox issuesCheckbox   = new TriStateCheckBox("Issues",   TriStateCheckBox.State.SELECTED);
    private final TriStateCheckBox trafficCheckbox  = new TriStateCheckBox("Traffic",  TriStateCheckBox.State.DESELECTED);

    // Settings sub (default both checked)
    private final JCheckBox settingsProjectCheckbox = new JCheckBox("Project", true);
    private final JCheckBox settingsUserCheckbox    = new JCheckBox("User", true);

    // Traffic sub (default none; user opts in); order matches alphabetical display
    private final JCheckBox trafficBurpAiCheckbox       = new JCheckBox("Burp AI", false);
    private final JCheckBox trafficExtensionsCheckbox   = new JCheckBox("Extensions", false);
    private final JCheckBox trafficIntruderCheckbox    = new JCheckBox("Intruder", false);
    private final JCheckBox trafficProxyCheckbox        = new JCheckBox("Proxy", false);
    private final JCheckBox trafficProxyHistoryCheckbox  = new JCheckBox("Proxy History", false);
    private final JCheckBox trafficRepeaterCheckbox    = new JCheckBox("Repeater", false);
    private final JCheckBox trafficScannerCheckbox      = new JCheckBox("Scanner", false);
    private final JCheckBox trafficSequencerCheckbox     = new JCheckBox("Sequencer", false);

    // Issues sub (default all severities checked)
    private final JCheckBox issuesCriticalCheckbox      = new JCheckBox("Critical", true);
    private final JCheckBox issuesHighCheckbox          = new JCheckBox("High", true);
    private final JCheckBox issuesMediumCheckbox        = new JCheckBox("Medium", true);
    private final JCheckBox issuesLowCheckbox           = new JCheckBox("Low", true);
    private final JCheckBox issuesInformationalCheckbox = new JCheckBox("Informational", true);

    private static final String EXPAND_COLLAPSED = "+";
    private static final String EXPAND_EXPANDED = "−";
    private final JButton settingsExpandButton = new JButton(EXPAND_COLLAPSED);
    private final JButton issuesExpandButton   = new JButton(EXPAND_COLLAPSED);
    private final JButton trafficExpandButton  = new JButton(EXPAND_COLLAPSED);

    private void configureExpandButton(JButton b) {
        b.setBorderPainted(false);
        b.setContentAreaFilled(false);
        b.setFocusPainted(false);
        b.setOpaque(false);
        b.setMargin(new java.awt.Insets(0, 0, 0, 0));
        b.setFocusable(false);
        b.setFont(b.getFont().deriveFont(Font.PLAIN, 22f));
    }

    // ---- Scope
    private final JRadioButton allRadio       = new JRadioButton("All");
    private final JRadioButton burpSuiteRadio = new JRadioButton("Burp Suite's", true);
    private final JRadioButton customRadio    = new JRadioButton("Custom");

    /** Pure grid of custom rows (field, regex toggle+indicator, add/delete). */
    private final ScopeGrid scopeGrid = new ScopeGrid(
            List.of(new ScopeGrid.ScopeEntryInit("^.*acme\\.com$", true))
    );

    // ---- Sinks
    private final JCheckBox fileSinkCheckbox = new JCheckBox("Files", false);
    private final JTextField filePathField   = new AutoSizingTextField("/path/to/directory");
    private final JButton    createFilesButton = new JButton("Create Files");
    private final JTextArea  fileStatus = new JTextArea();
    private final JPanel     fileStatusWrapper
            = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

    private final JCheckBox  openSearchSinkCheckbox = new JCheckBox("OpenSearch", true);
    private final JTextField openSearchUrlField     = new AutoSizingTextField("http://opensearch.url:9200");
    private final JButton    testConnectionButton   = new JButton("Test Connection");
    private final JButton    createIndexesButton    = new JButton("Create Indexes");
    private final JTextArea  openSearchStatus       = new JTextArea();
    private final JPanel     openSearchStatusWrapper
            = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

    // ---- Control
    private final JTextArea controlStatus = new JTextArea();
    private final JPanel    controlStatusWrapper
            = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));
    private transient Timer controlStatusHideTimer;

    /** Action controller (transient; rebuilt on deserialization). */
    private transient ConfigController controller = new ConfigController(this);

    /** Public no-arg constructor (EDT). */
    public ConfigPanel() { this(null); }

    /** Dependency-injected constructor (tests). */
    public ConfigPanel(ConfigController injectedController) {
        if (injectedController != null) this.controller = injectedController;

        setLayout(new MigLayout("fillx, insets 12", "[fill]"));

        assignToolTips();

        // Sources: build sub-panels and wire expand/collapse (default collapsed)
        configureExpandButton(settingsExpandButton);
        configureExpandButton(issuesExpandButton);
        configureExpandButton(trafficExpandButton);

        JPanel settingsSubPanel = buildSettingsSubPanel();
        JPanel issuesSubPanel = buildIssuesSubPanel();
        JPanel trafficSubPanel = buildTrafficSubPanel();
        settingsSubPanel.setOpaque(false);
        issuesSubPanel.setOpaque(false);
        trafficSubPanel.setOpaque(false);
        settingsSubPanel.setVisible(false);
        issuesSubPanel.setVisible(false);
        trafficSubPanel.setVisible(false);
        wireSourcesExpandCollapse(settingsExpandButton, settingsSubPanel);
        wireSourcesExpandCollapse(issuesExpandButton, issuesSubPanel);
        wireSourcesExpandCollapse(trafficExpandButton, trafficSubPanel);

        wireTriStateParentChild(settingsCheckbox, java.util.List.of(settingsProjectCheckbox, settingsUserCheckbox));
        wireTriStateParentChild(issuesCheckbox, java.util.List.of(
                issuesCriticalCheckbox, issuesHighCheckbox, issuesMediumCheckbox, issuesLowCheckbox, issuesInformationalCheckbox));
        wireTriStateParentChild(trafficCheckbox, java.util.List.of(
                trafficBurpAiCheckbox, trafficExtensionsCheckbox, trafficIntruderCheckbox, trafficProxyCheckbox,
                trafficProxyHistoryCheckbox, trafficRepeaterCheckbox, trafficScannerCheckbox, trafficSequencerCheckbox));

        add(new ConfigSourcesPanel(settingsCheckbox, sitemapCheckbox, issuesCheckbox, trafficCheckbox,
                settingsExpandButton, settingsSubPanel, issuesExpandButton, issuesSubPanel,
                trafficExpandButton, trafficSubPanel, INDENT).build(),
                "gaptop 5, gapbottom 5, wrap");
        add(panelSeparator(), MIG_FILL_WRAP);

        // Scope
        add(new ConfigScopePanel(allRadio, burpSuiteRadio, customRadio, scopeGrid, INDENT).build(),
                "gaptop 10, gapbottom 5, wrap");
        add(panelSeparator(), MIG_FILL_WRAP);

        // Sinks
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
                StatusViews::configureTextArea
        ).build(), "gaptop 10, gapbottom 5, wrap");

        wireButtonActions();
        add(panelSeparator(), MIG_FILL_WRAP);

        // Control
        add(new ConfigControlPanel(
                new JTextArea(),
                new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL)),
                controlStatus,
                controlStatusWrapper,
                INDENT,
                ROW_GAP,
                StatusViews::configureTextArea,
                this::importConfig,
                this::exportConfig,
                new ControlSaveButtonListener(),
                () -> {
                    updateRuntimeConfig();
                    RuntimeConfig.setExportRunning(true);
                    ToolIndexConfigReporter.pushConfigSnapshot();
                    ToolIndexStatsReporter.start();
                    SettingsIndexReporter.pushSnapshotNow();
                    SettingsIndexReporter.start();
                    FindingsIndexReporter.start();
                    FindingsIndexReporter.pushSnapshotNow();
                    SitemapIndexReporter.start();
                    SitemapIndexReporter.pushSnapshotNow();
                    ProxyHistoryIndexReporter.pushSnapshotNow();
                    Logger.logInfoPanelOnly("Export started.");
                },
                () -> {
                    RuntimeConfig.setExportRunning(false);
                    Logger.logInfoPanelOnly("Export stopped.");
                }
        ).build(), MIG_FILL_WRAP);

        add(Box.createVerticalGlue(), "growy, wrap");

        assignComponentNames();
        wireTextFieldEnhancements();
        scopeGrid.setOnContentChange(this::updateRuntimeConfig);
        refreshEnabledStates();
        applyEditionRestrictions();
    }

    /**
     * Disables the Issues checkbox when Burp is Community edition (Scanner/issues
     * not populated). Call after panel is built; no-op if API is not yet available.
     */
    private void applyEditionRestrictions() {
        MontoyaApi api = MontoyaApiProvider.get();
        if (api == null) {
            return;
        }
        if (api.burpSuite().version().edition() == BurpSuiteEdition.COMMUNITY_EDITION) {
            issuesCheckbox.setEnabled(false);
            issuesCheckbox.setToolTipText("Not available with Community license");
        }
    }

    /**
     * Creates a separator used between major configuration blocks.
     *
     * @return new separator component
     */
    private JComponent panelSeparator() { return new ThickSeparator(); }

    /* ----------------------- ConfigController.Ui ----------------------- */

    /**
     * Updates the Files status area on the EDT with the provided message.
     *
     * <p>
     * @param message status text to display (nullable)
     */
    @Override public void onFileStatus(String message) {
        StatusViews.setStatus(
                fileStatus, fileStatusWrapper, message, STATUS_MIN_COLS, STATUS_MAX_COLS);
    }

    /**
     * Updates the OpenSearch status area on the EDT with the provided message.
     *
     * <p>
     * @param message status text to display (nullable)
     */
    @Override public void onOpenSearchStatus(String message) {
        StatusViews.setStatus(
                openSearchStatus, openSearchStatusWrapper, message, STATUS_MIN_COLS, STATUS_MAX_COLS);
    }

    /**
     * Updates the Control status area on the EDT and auto-hides after a delay.
     *
     * <p>
     * @param message status text to display (nullable)
     */
    @Override public void onControlStatus(String message) {
        Runnable r = () -> {
            StatusViews.setStatus(
                    controlStatus, controlStatusWrapper, message, STATUS_MIN_COLS, STATUS_MAX_COLS);
            if (controlStatusHideTimer != null && controlStatusHideTimer.isRunning()) controlStatusHideTimer.stop();
            controlStatusHideTimer = new Timer(CONTROL_HIDE_DELAY_MS, evt -> {
                controlStatusWrapper.setVisible(false);
                controlStatusWrapper.revalidate();
                controlStatusWrapper.repaint();
            });
            controlStatusHideTimer.setRepeats(false);
            controlStatusHideTimer.start();
        };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else {
            try { SwingUtilities.invokeAndWait(r); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); SwingUtilities.invokeLater(r); }
            catch (Exception ex) { SwingUtilities.invokeLater(r); }
        }
    }

    /* ----------------------- Import plumbing (not Ui) ----------------------- */

    /**
     * Applies an imported state to the UI.
     *
     * <p>For custom scope, rows are applied first and then the Custom radio is selected to ensure
     * enablement is updated on the final state.</p>
     */
    public void onImportResult(ConfigState.State state) {
        Runnable r = () -> {
            settingsCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_SETTINGS));
            sitemapCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_SITEMAP));
            issuesCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_FINDINGS));
            trafficCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_TRAFFIC));

            List<String> settingsSub = state.settingsSub() != null ? state.settingsSub() : List.of();
            settingsProjectCheckbox.setSelected(settingsSub.contains(ConfigKeys.SRC_SETTINGS_PROJECT));
            settingsUserCheckbox.setSelected(settingsSub.contains(ConfigKeys.SRC_SETTINGS_USER));

            List<String> trafficTools = state.trafficToolTypes() != null ? state.trafficToolTypes() : List.of();
            trafficBurpAiCheckbox.setSelected(trafficTools.contains("BURP_AI"));
            trafficExtensionsCheckbox.setSelected(trafficTools.contains("EXTENSIONS"));
            trafficIntruderCheckbox.setSelected(trafficTools.contains("INTRUDER"));
            trafficProxyCheckbox.setSelected(trafficTools.contains("PROXY"));
            trafficProxyHistoryCheckbox.setSelected(trafficTools.contains("PROXY_HISTORY"));
            trafficRepeaterCheckbox.setSelected(trafficTools.contains("REPEATER"));
            trafficScannerCheckbox.setSelected(trafficTools.contains("SCANNER"));
            trafficSequencerCheckbox.setSelected(trafficTools.contains("SEQUENCER"));

            List<String> severities = state.findingsSeverities() != null ? state.findingsSeverities() : List.of();
            issuesCriticalCheckbox.setSelected(severities.contains("CRITICAL"));
            issuesHighCheckbox.setSelected(severities.contains("HIGH"));
            issuesMediumCheckbox.setSelected(severities.contains("MEDIUM"));
            issuesLowCheckbox.setSelected(severities.contains("LOW"));
            issuesInformationalCheckbox.setSelected(severities.contains("INFORMATIONAL"));

            switch (state.scopeType()) {
                case ConfigKeys.SCOPE_CUSTOM -> {
                    List<ScopeGrid.ScopeEntryInit> init = new ArrayList<>();
                    for (ConfigState.ScopeEntry ce : state.customEntries()) {
                        boolean isRegex = ce.kind() == ConfigState.Kind.REGEX;
                        init.add(new ScopeGrid.ScopeEntryInit(ce.value(), isRegex));
                    }
                    if (init.isEmpty()) init.add(new ScopeGrid.ScopeEntryInit("", true));
                    scopeGrid.setEntries(init);
                    customRadio.setSelected(true);
                }
                case ConfigKeys.SCOPE_BURP -> burpSuiteRadio.setSelected(true);
                default -> allRadio.setSelected(true);
            }

            refreshEnabledStates();
            updateRuntimeConfig();
        };
        runOnEdt(r);
    }

    private void updateRuntimeConfig() {
        RuntimeConfig.updateState(buildCurrentState());
    }

    /* ----------------------------- Wiring ----------------------------- */

    /**
     * Wires button and checkbox actions for sinks and layout relayout hooks.
     *
     * <p>Caller must invoke on the EDT. Validates required fields before delegating to
     * {@link ConfigController} and keeps text fields revalidated as their contents change.</p>
     */
    private void wireButtonActions() {
        ActionListener runtimeUpdater = e -> updateRuntimeConfig();
        ActionListener sinkUpdater = e -> {
            refreshEnabledStates();
            updateRuntimeConfig();
        };

        settingsCheckbox.addActionListener(runtimeUpdater);
        sitemapCheckbox.addActionListener(runtimeUpdater);
        issuesCheckbox.addActionListener(runtimeUpdater);
        trafficCheckbox.addActionListener(runtimeUpdater);
        settingsProjectCheckbox.addActionListener(runtimeUpdater);
        settingsUserCheckbox.addActionListener(runtimeUpdater);
        trafficBurpAiCheckbox.addActionListener(runtimeUpdater);
        trafficExtensionsCheckbox.addActionListener(runtimeUpdater);
        trafficIntruderCheckbox.addActionListener(runtimeUpdater);
        trafficProxyCheckbox.addActionListener(runtimeUpdater);
        trafficProxyHistoryCheckbox.addActionListener(runtimeUpdater);
        trafficRepeaterCheckbox.addActionListener(runtimeUpdater);
        trafficScannerCheckbox.addActionListener(runtimeUpdater);
        trafficSequencerCheckbox.addActionListener(runtimeUpdater);
        issuesCriticalCheckbox.addActionListener(runtimeUpdater);
        issuesHighCheckbox.addActionListener(runtimeUpdater);
        issuesMediumCheckbox.addActionListener(runtimeUpdater);
        issuesLowCheckbox.addActionListener(runtimeUpdater);
        issuesInformationalCheckbox.addActionListener(runtimeUpdater);

        allRadio.addActionListener(runtimeUpdater);
        burpSuiteRadio.addActionListener(runtimeUpdater);
        customRadio.addActionListener(runtimeUpdater);

        fileSinkCheckbox.addActionListener(sinkUpdater);
        openSearchSinkCheckbox.addActionListener(sinkUpdater);

        createFilesButton.addActionListener(e -> {
            updateRuntimeConfig();
            String root = filePathField.getText().trim();
            if (root.isEmpty()) { onFileStatus("✖ Path required"); return; }
            controller.createFilesAsync(root, getSelectedSources());
        });

        testConnectionButton.addActionListener(e -> {
            updateRuntimeConfig();
            String url = openSearchUrlField.getText().trim();
            if (url.isEmpty()) { onOpenSearchStatus("✖ URL required"); return; }
            controller.testConnectionAsync(url);
        });

        createIndexesButton.addActionListener(e -> {
            updateRuntimeConfig();
            String url = openSearchUrlField.getText().trim();
            if (url.isEmpty()) { onOpenSearchStatus("✖ URL required"); return; }
            onOpenSearchStatus("Creating ...");
            controller.createIndexesAsync(url, getSelectedSources());
        });

        DocumentListener relayout = Doc.onChange(() -> {
            filePathField.revalidate();
            openSearchUrlField.revalidate();
            updateRuntimeConfig();
        });
        filePathField.getDocument().addDocumentListener(relayout);
        openSearchUrlField.getDocument().addDocumentListener(relayout);
    }

    private JPanel buildSettingsSubPanel() {
        JPanel p = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        p.add(settingsProjectCheckbox);
        p.add(settingsUserCheckbox);
        return p;
    }

    private JPanel buildIssuesSubPanel() {
        JPanel p = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        p.add(issuesCriticalCheckbox);
        p.add(issuesHighCheckbox);
        p.add(issuesMediumCheckbox);
        p.add(issuesLowCheckbox);
        p.add(issuesInformationalCheckbox);
        return p;
    }

    private JPanel buildTrafficSubPanel() {
        JPanel p = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        p.add(trafficBurpAiCheckbox);
        p.add(trafficExtensionsCheckbox);
        p.add(trafficIntruderCheckbox);
        p.add(trafficProxyCheckbox);
        p.add(trafficProxyHistoryCheckbox);
        p.add(trafficRepeaterCheckbox);
        p.add(trafficScannerCheckbox);
        p.add(trafficSequencerCheckbox);
        return p;
    }

    private void wireSourcesExpandCollapse(JButton expandButton, JPanel subPanel) {
        expandButton.addActionListener(e -> {
            boolean show = !subPanel.isVisible();
            subPanel.setVisible(show);
            expandButton.setText(show ? EXPAND_EXPANDED : EXPAND_COLLAPSED);
            subPanel.revalidate();
            subPanel.repaint();
        });
    }

    private void wireTriStateParentChild(TriStateCheckBox parent, java.util.List<JCheckBox> children) {
        java.util.concurrent.atomic.AtomicBoolean syncing = new java.util.concurrent.atomic.AtomicBoolean(false);

        Runnable syncParentFromChildren = () -> {
            if (children == null || children.isEmpty()) {
                return;
            }
            int selected = 0;
            for (JCheckBox c : children) {
                if (c.isSelected()) {
                    selected++;
                }
            }
            if (selected == 0) {
                parent.setState(TriStateCheckBox.State.DESELECTED);
            } else if (selected == children.size()) {
                parent.setState(TriStateCheckBox.State.SELECTED);
            } else {
                parent.setState(TriStateCheckBox.State.INDETERMINATE);
            }
        };

        // Children -> parent state
        for (JCheckBox child : children) {
            child.addActionListener(e -> {
                if (syncing.get()) {
                    return;
                }
                syncing.set(true);
                try {
                    syncParentFromChildren.run();
                } finally {
                    syncing.set(false);
                }
            });
        }

        // Parent -> children (select all / deselect all)
        parent.addActionListener(e -> {
            if (syncing.get()) {
                return;
            }
            syncing.set(true);
            try {
                boolean selectAll = parent.getState() != TriStateCheckBox.State.DESELECTED;
                for (JCheckBox child : children) {
                    child.setSelected(selectAll);
                }
                syncParentFromChildren.run();
            } finally {
                syncing.set(false);
            }
        });

        // Initial sync
        syncing.set(true);
        try {
            syncParentFromChildren.run();
        } finally {
            syncing.set(false);
        }
    }

    /**
     * Enables/disables sink controls based on checkbox selections.
     *
     * <p>EDT only. Keeps paired text fields and buttons in sync with their enable toggles.</p>
     */
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
     * Collects the currently selected data sources.
     *
     * <p>
     * @return ordered list of source keys suitable for {@link ConfigKeys}
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
     * Installs undo/redo bindings and enter-key shortcuts on text fields.
     *
     * <p>EDT only. Enter triggers the most relevant action for each field.</p>
     */
    private void wireTextFieldEnhancements() {
        TextFieldUndo.install(filePathField);
        TextFieldUndo.install(openSearchUrlField);
        filePathField.addActionListener(e -> createFilesButton.doClick());
        openSearchUrlField.addActionListener(e -> testConnectionButton.doClick());
    }

    /**
     * Builds the current UI state into a serializable config object.
     *
     * <p>
     * @return assembled {@link ConfigState.State} reflecting user selections
     */
    private ConfigState.State buildCurrentState() {
        List<String> selectedSources = getSelectedSources();

        String scopeType;
        List<ConfigState.ScopeEntry> custom = new ArrayList<>();
        if (allRadio.isSelected()) {
            scopeType = ConfigKeys.SCOPE_ALL;
        } else if (burpSuiteRadio.isSelected()) {
            scopeType = ConfigKeys.SCOPE_BURP;
        } else if (customRadio.isSelected()) {
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

        List<String> settingsSub = new ArrayList<>();
        if (settingsProjectCheckbox.isSelected()) settingsSub.add(ConfigKeys.SRC_SETTINGS_PROJECT);
        if (settingsUserCheckbox.isSelected()) settingsSub.add(ConfigKeys.SRC_SETTINGS_USER);

        List<String> trafficToolTypes = new ArrayList<>();
        if (trafficBurpAiCheckbox.isSelected()) trafficToolTypes.add("BURP_AI");
        if (trafficExtensionsCheckbox.isSelected()) trafficToolTypes.add("EXTENSIONS");
        if (trafficIntruderCheckbox.isSelected()) trafficToolTypes.add("INTRUDER");
        if (trafficProxyCheckbox.isSelected()) trafficToolTypes.add("PROXY");
        if (trafficProxyHistoryCheckbox.isSelected()) trafficToolTypes.add("PROXY_HISTORY");
        if (trafficRepeaterCheckbox.isSelected()) trafficToolTypes.add("REPEATER");
        if (trafficScannerCheckbox.isSelected()) trafficToolTypes.add("SCANNER");
        if (trafficSequencerCheckbox.isSelected()) trafficToolTypes.add("SEQUENCER");

        List<String> findingsSeverities = new ArrayList<>();
        if (issuesCriticalCheckbox.isSelected()) findingsSeverities.add("CRITICAL");
        if (issuesHighCheckbox.isSelected()) findingsSeverities.add("HIGH");
        if (issuesMediumCheckbox.isSelected()) findingsSeverities.add("MEDIUM");
        if (issuesLowCheckbox.isSelected()) findingsSeverities.add("LOW");
        if (issuesInformationalCheckbox.isSelected()) findingsSeverities.add("INFORMATIONAL");

        return new ConfigState.State(
                selectedSources,
                scopeType,
                custom,
                new ConfigState.Sinks(filesEnabled, filesRoot, osEnabled, osUrl),
                settingsSub,
                trafficToolTypes,
                findingsSeverities
        );
    }

    /**
     * Prompts for a save location and exports the current config to JSON asynchronously.
     *
     * <p>EDT only. Uses {@link FileUtil#ensureJsonExtension(java.io.File)} to normalize the file
     * name before delegating to {@link ConfigController#exportConfigAsync(java.nio.file.Path, String)}.</p>
     */
    private void exportConfig() {
        String json = ConfigJsonMapper.build(buildCurrentState());
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        chooser.setSelectedFile(new File("attackframework-burp-exporter-config.json"));
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) { onControlStatus("Export cancelled."); return; }
        Path out = FileUtil.ensureJsonExtension(chooser.getSelectedFile()).toPath();
        controller.exportConfigAsync(out, json);
    }

    /**
     * Prompts for a config file and imports it asynchronously via the controller.
     *
     * <p>EDT only. Delegates parsing and UI application to
     * {@link ConfigController#importConfigAsync(java.nio.file.Path)}.</p>
     */
    private void importConfig() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) { onControlStatus("Import cancelled."); return; }
        controller.importConfigAsync(chooser.getSelectedFile().toPath());
    }

    /** Assign stable names used by headless tests. */
    private void assignComponentNames() {
        settingsCheckbox.setName("src.settings");
        sitemapCheckbox.setName("src.sitemap");
        issuesCheckbox.setName("src.issues");
        trafficCheckbox.setName("src.traffic");
        settingsProjectCheckbox.setName("src.settings.project");
        settingsUserCheckbox.setName("src.settings.user");
        settingsExpandButton.setName("src.settings.expand");
        issuesCriticalCheckbox.setName("src.issues.critical");
        issuesHighCheckbox.setName("src.issues.high");
        issuesMediumCheckbox.setName("src.issues.medium");
        issuesLowCheckbox.setName("src.issues.low");
        issuesInformationalCheckbox.setName("src.issues.informational");
        issuesExpandButton.setName("src.issues.expand");
        trafficBurpAiCheckbox.setName("src.traffic.burp_ai");
        trafficExtensionsCheckbox.setName("src.traffic.extensions");
        trafficIntruderCheckbox.setName("src.traffic.intruder");
        trafficProxyCheckbox.setName("src.traffic.proxy");
        trafficProxyHistoryCheckbox.setName("src.traffic.proxy_history");
        trafficRepeaterCheckbox.setName("src.traffic.repeater");
        trafficScannerCheckbox.setName("src.traffic.scanner");
        trafficSequencerCheckbox.setName("src.traffic.sequencer");
        trafficExpandButton.setName("src.traffic.expand");

        allRadio.setName("scope.all");
        burpSuiteRadio.setName("scope.burp");
        customRadio.setName("scope.custom");

        fileSinkCheckbox.setName("files.enable");
        filePathField.setName("files.path");
        createFilesButton.setName("files.create");

        openSearchSinkCheckbox.setName("os.enable");
        openSearchUrlField.setName("os.url");
        testConnectionButton.setName("os.test");
        createIndexesButton.setName("os.createIndexes");

        controlStatusWrapper.setName("control.statusWrapper");
        controlStatus.setName("control.status");
    }

    /**
     * Assigns tooltips for all ConfigPanel controls.
     *
     * <p>EDT only. Consolidated here to keep tooltip text consistent and discoverable.</p>
     */
    private void assignToolTips() {
        settingsCheckbox.setToolTipText("Include settings exports");
        sitemapCheckbox.setToolTipText("Include sitemap exports");
        issuesCheckbox.setToolTipText("Include findings exports");
        trafficCheckbox.setToolTipText("Include traffic exports");
        settingsExpandButton.setToolTipText("Expand or collapse Settings sub-options");
        issuesExpandButton.setToolTipText("Expand or collapse Issues severity filters");
        trafficExpandButton.setToolTipText("Expand or collapse Traffic source filters");
        settingsProjectCheckbox.setToolTipText("Include project-level settings in settings export");
        settingsUserCheckbox.setToolTipText("Include user-level settings in settings export");
        trafficBurpAiCheckbox.setToolTipText("Export traffic sent from Burp AI");
        trafficExtensionsCheckbox.setToolTipText("Export traffic sent from all other extensions");
        trafficIntruderCheckbox.setToolTipText("Export traffic sent from Intruder");
        trafficProxyCheckbox.setToolTipText("Export traffic sent from Proxy");
        trafficProxyHistoryCheckbox.setToolTipText("One-time export of Proxy History upon start. For ongoing traffic, select Proxy.");
        trafficRepeaterCheckbox.setToolTipText("Export traffic sent from Repeater");
        trafficScannerCheckbox.setToolTipText("Export traffic sent from Scanner");
        trafficSequencerCheckbox.setToolTipText("Export traffic sent from Sequencer");

        allRadio.setToolTipText("Export all observed");
        burpSuiteRadio.setToolTipText("Export Burp Suite's project scope");
        customRadio.setToolTipText("Export custom scope");

        fileSinkCheckbox.setToolTipText("Enable file-based export");
        filePathField.setToolTipText("Root directory for generated files");
        createFilesButton.setToolTipText("Test file creation. Not required.");

        openSearchSinkCheckbox.setToolTipText("Enable OpenSearch export");
        openSearchUrlField.setToolTipText("Base URL of the OpenSearch cluster");
        testConnectionButton.setToolTipText("Test connectivity to OpenSearch");
        createIndexesButton.setToolTipText("Test index creation. Not required.");
    }

    /**
     * Save button handler: applies current UI state to runtime immediately so
     * traffic and tool index use the new config (e.g. scope) without restarting
     * export; persists via controller; triggers one tool index stats push when
     * export is running so the next snapshot reflects the saved config.
     */
    private class ControlSaveButtonListener implements ActionListener {
        @Override public void actionPerformed(ActionEvent e) {
            updateRuntimeConfig();
            if (RuntimeConfig.isExportRunning()) {
                ToolIndexConfigReporter.pushConfigSnapshot();
                ToolIndexStatsReporter.pushSnapshotNow();
            }
            controller.saveAsync(buildCurrentState());
        }
    }

    /**
     * Runs a task on the EDT, executing immediately when already on the EDT.
     *
     * <p>
     * @param r task to run
     */
    private void runOnEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    /** Rebuild transient collaborators after deserialization. */
    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        this.controller = new ConfigController(this);
    }

}
