package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.sinks.FileExportService;
import ai.attackframework.tools.burp.sinks.FindingsIndexReporter;
import ai.attackframework.tools.burp.sinks.OpenSearchSink;
import ai.attackframework.tools.burp.sinks.ProxyHistoryIndexReporter;
import ai.attackframework.tools.burp.sinks.ProxyWebSocketIndexReporter;
import ai.attackframework.tools.burp.sinks.SettingsIndexReporter;
import ai.attackframework.tools.burp.sinks.SitemapIndexReporter;
import ai.attackframework.tools.burp.sinks.ToolIndexConfigReporter;
import ai.attackframework.tools.burp.sinks.ToolIndexStatsReporter;
import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.ui.primitives.AutoSizingPasswordField;
import ai.attackframework.tools.burp.ui.primitives.AutoSizingTextField;
import ai.attackframework.tools.burp.ui.primitives.ButtonStyles;
import ai.attackframework.tools.burp.ui.primitives.ScopeGrid;
import ai.attackframework.tools.burp.ui.primitives.StatusViews;
import ai.attackframework.tools.burp.ui.primitives.TextFieldUndo;
import ai.attackframework.tools.burp.ui.primitives.ThickSeparator;
import ai.attackframework.tools.burp.ui.primitives.TriStateCheckBox;
import ai.attackframework.tools.burp.ui.text.Doc;
import ai.attackframework.tools.burp.ui.text.ExportFieldTooltips;
import ai.attackframework.tools.burp.ui.text.Tooltips;
import ai.attackframework.tools.burp.utils.ControlStatusBridge;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.config.SecureCredentialStore;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import net.miginfocom.swing.MigLayout;

/**
 * Main configuration panel for data sources, scope, destination, and control actions.
 *
 * <p><strong>Responsibilities:</strong> render the UI, compose/parse {@link ConfigState.State},
 * and delegate long-running work to {@link ConfigController}.</p>
 *
 * <p><strong>Threading:</strong> callers construct and interact with this panel on the EDT.</p>
 */
public class ConfigPanel extends JPanel implements ConfigController.Ui {

    @Serial private static final long serialVersionUID = 1L;

    private static final int INDENT = 30;
    private static final int ROW_GAP = 15;
    private static final String MIG_STATUS_INSETS = "insets 5, novisualpadding";
    private static final String MIG_PREF_COL = "[pref!]";
    private static final String MIG_FILL_WRAP = "growx, wrap";
    private static final int STATUS_MIN_COLS = 20;
    private static final int STATUS_MAX_COLS = 200;
    private static final long GIB_BYTES = 1024L * 1024L * 1024L;
    private static final BigDecimal GIB_BYTES_DECIMAL = BigDecimal.valueOf(GIB_BYTES);
    /** Background executor for Start-path OpenSearch bootstrap work. */
    private static final ExecutorService STARTUP_EXECUTOR = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "attackframework-startup");
        t.setDaemon(true);
        return t;
    });

    private final TriStateCheckBox settingsCheckbox = new TriStateCheckBox("Settings", TriStateCheckBox.State.SELECTED);
    private final JCheckBox sitemapCheckbox  = new Tooltips.HtmlCheckBox("Sitemap",  true);
    private final TriStateCheckBox issuesCheckbox   = new TriStateCheckBox("Issues",   TriStateCheckBox.State.SELECTED);
    private final TriStateCheckBox trafficCheckbox  = new TriStateCheckBox("Traffic",  TriStateCheckBox.State.DESELECTED);

    private final JCheckBox settingsProjectCheckbox = new Tooltips.HtmlCheckBox("Project", true);
    private final JCheckBox settingsUserCheckbox    = new Tooltips.HtmlCheckBox("User", true);

    private final JCheckBox trafficBurpAiCheckbox       = new Tooltips.HtmlCheckBox("Burp AI", false);
    private final JCheckBox trafficExtensionsCheckbox   = new Tooltips.HtmlCheckBox("Extensions", false);
    private final JCheckBox trafficIntruderCheckbox    = new Tooltips.HtmlCheckBox("Intruder", false);
    private final JCheckBox trafficProxyCheckbox        = new Tooltips.HtmlCheckBox("Proxy", false);
    private final JCheckBox trafficProxyHistoryCheckbox  = new Tooltips.HtmlCheckBox("Proxy History", false);
    private final JCheckBox trafficRepeaterCheckbox    = new Tooltips.HtmlCheckBox("Repeater", false);
    private final JCheckBox trafficScannerCheckbox      = new Tooltips.HtmlCheckBox("Scanner", false);
    private final JCheckBox trafficSequencerCheckbox     = new Tooltips.HtmlCheckBox("Sequencer", false);

    private final JCheckBox issuesCriticalCheckbox      = new Tooltips.HtmlCheckBox("Critical", true);
    private final JCheckBox issuesHighCheckbox          = new Tooltips.HtmlCheckBox("High", true);
    private final JCheckBox issuesMediumCheckbox        = new Tooltips.HtmlCheckBox("Medium", true);
    private final JCheckBox issuesLowCheckbox           = new Tooltips.HtmlCheckBox("Low", true);
    private final JCheckBox issuesInformationalCheckbox = new Tooltips.HtmlCheckBox("Informational", true);

    private static final String EXPAND_COLLAPSED = "+";
    private static final String EXPAND_EXPANDED = "−";
    private final JButton settingsExpandButton = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
    private final JButton issuesExpandButton   = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
    private final JButton trafficExpandButton  = new Tooltips.HtmlButton(EXPAND_COLLAPSED);

    private final JRadioButton allRadio       = new Tooltips.HtmlRadioButton("All");
    private final JRadioButton burpSuiteRadio = new Tooltips.HtmlRadioButton("Burp Suite's", true);
    private final JRadioButton customRadio    = new Tooltips.HtmlRadioButton("Custom");

    /** Pure grid of custom rows (field, regex toggle+indicator, add/delete). */
    private final ScopeGrid scopeGrid = new ScopeGrid(
            List.of(new ScopeGrid.ScopeEntryInit("^.*acme\\.com$", true))
    );

    private final JCheckBox fileSinkCheckbox = new Tooltips.HtmlCheckBox("Files", false);
    private final JTextField filePathField   = new AutoSizingTextField("/path/to/directory");
    private final JRadioButton fileJsonlCheckbox = new Tooltips.HtmlRadioButton("JSONL");
    private final JRadioButton fileBulkNdjsonCheckbox = new Tooltips.HtmlRadioButton("NDJSON", true);
    private final ButtonGroup fileFormatGroup = new ButtonGroup();
    private final JCheckBox fileTotalCapCheckbox = new Tooltips.HtmlCheckBox("Max total file size:", true);
    private final JTextField fileTotalCapField = new AutoSizingTextField("10");
    private final JCheckBox fileDiskUsagePercentCheckbox = new Tooltips.HtmlCheckBox("Disk usage:", true);
    private final JTextField fileDiskUsagePercentField = new AutoSizingTextField("95");

    private final JCheckBox  openSearchSinkCheckbox = new Tooltips.HtmlCheckBox("OpenSearch", true);
    private final JTextField openSearchUrlField     = new AutoSizingTextField("https://opensearch.url:9200");
    private final JCheckBox  openSearchInsecureSslCheckbox = new Tooltips.HtmlCheckBox("Accept self-signed cert", true);
    private final JButton    testConnectionButton   = new Tooltips.HtmlButton("Test Connection");
    /** OpenSearch auth controls panel (inline on the OpenSearch row). Built in {@link #buildAuthFormPanel()}. */
    private JPanel           openSearchAuthFormPanel;
    /** Auth type dropdown (used in buildCurrentState to clear creds when None). Set in buildAuthFormPanel. */
    private JComboBox<String> openSearchAuthTypeCombo;
    /** Basic auth fields (used in auth form and buildCurrentState). */
    private final JTextField openSearchUserField   = new AutoSizingTextField("");
    private final JPasswordField openSearchPasswordField = new AutoSizingPasswordField();
    /** API key auth fields. */
    private final JTextField openSearchApiKeyIdField = new AutoSizingTextField("");
    private final JPasswordField openSearchApiKeySecretField = new AutoSizingPasswordField();
    /** JWT auth field. */
    private final JTextField openSearchJwtTokenField = new AutoSizingTextField("");
    /** Certificate auth fields. */
    private final JTextField openSearchCertPathField = new AutoSizingTextField("");
    private final JTextField openSearchCertKeyPathField = new AutoSizingTextField("");
    private final JPasswordField openSearchCertPassphraseField = new AutoSizingPasswordField();
    private final JTextArea  openSearchStatus       = new JTextArea();
    private final JPanel     openSearchStatusWrapper
            = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

    private final JTextArea controlStatus = new JTextArea();
    private final JPanel    controlStatusWrapper
            = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));
    private transient boolean scopeGridListenerRegistered;
    private transient boolean buttonStylesNormalized;

    /** Action controller (transient; rebuilt on deserialization). */
    private transient ConfigController controller;

    /** Fields panel: index -> (fieldKey -> checkbox). Populated in constructor when building Fields section. */
    private java.util.Map<String, java.util.Map<String, JCheckBox>> fieldCheckboxesByIndex;
    /** Fields panel: index -> expand button; used for enable/disable when Data Source is toggled. */
    private java.util.Map<String, JButton> fieldsExpandButtons;
    /** Fields panel: index -> sub-panel of checkboxes; used for enable/disable when Data Source is toggled. */
    private java.util.Map<String, JPanel> fieldsSubPanels;
    /** Fields panel: index -> header row panel (label + expand button); used for enable/disable when Data Source is toggled. */
    private java.util.Map<String, JPanel> fieldsSectionHeaderRows;

    /** Public no-arg constructor (EDT). */
    public ConfigPanel() { this(null); }

    /** Dependency-injected constructor (tests). */
    public ConfigPanel(ConfigController injectedController) {
        this.controller = injectedController;
        ControlStatusBridge.register(this::onControlStatus);

        setLayout(new MigLayout("fillx, insets 12", "[fill]"));

        assignToolTips();
        configureFileFormatButtons();

        ButtonStyles.configureExpandButton(settingsExpandButton);
        ButtonStyles.configureExpandButton(issuesExpandButton);
        ButtonStyles.configureExpandButton(trafficExpandButton);

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

        fieldCheckboxesByIndex = new java.util.LinkedHashMap<>();
        fieldsExpandButtons = new java.util.LinkedHashMap<>();
        fieldsSubPanels = new java.util.LinkedHashMap<>();
        fieldsSectionHeaderRows = new java.util.LinkedHashMap<>();
        List<String> fieldsPanelIndexOrder = ai.attackframework.tools.burp.utils.config.ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL;
        for (String indexName : fieldsPanelIndexOrder) {
            java.util.Map<String, JCheckBox> perIndex = new java.util.LinkedHashMap<>();
            List<String> toggleable = new java.util.ArrayList<>(ai.attackframework.tools.burp.utils.config.ExportFieldRegistry.getToggleableFields(indexName));
            for (String fieldKey : toggleable) {
                JCheckBox cb = new Tooltips.HtmlCheckBox(ExportFieldTooltips.displayNameFor(indexName, fieldKey), true);
                cb.setName("fields." + indexName + "." + fieldKey);
                Tooltips.apply(cb, ExportFieldTooltips.tooltipFor(indexName, fieldKey));
                perIndex.put(fieldKey, cb);
            }
            fieldCheckboxesByIndex.put(indexName, perIndex);
            JButton expBtn = new Tooltips.HtmlButton("+");
            expBtn.setName("fields." + indexName + ".expand");
            ConfigFieldsPanel.configureExpandButton(expBtn);
            fieldsExpandButtons.put(indexName, expBtn);
            JPanel sub = new JPanel(new MigLayout("insets 0, wrap 3", "[left][left][left]"));
            sub.setOpaque(false);
            for (JCheckBox cb : perIndex.values()) {
                sub.add(cb, "gapright 12");
            }
            sub.setVisible(false);
            fieldsSubPanels.put(indexName, sub);
        }
        ActionListener fieldsRuntimeUpdater = e -> updateRuntimeConfig();
        for (String indexName : fieldsPanelIndexOrder) {
            JButton expBtn = fieldsExpandButtons.get(indexName);
            JPanel sub = fieldsSubPanels.get(indexName);
            wireSourcesExpandCollapse(expBtn, sub);
            for (JCheckBox cb : fieldCheckboxesByIndex.get(indexName).values()) {
                cb.addActionListener(fieldsRuntimeUpdater);
            }
        }
        JPanel fieldsPanel = new ConfigFieldsPanel(fieldsExpandButtons, fieldsSubPanels, INDENT).build(fieldsSectionHeaderRows);

        add(new ConfigScopePanel(allRadio, burpSuiteRadio, customRadio, scopeGrid, INDENT).build(),
                "gaptop 10, gapbottom 5, wrap");
        add(panelSeparator(), MIG_FILL_WRAP);

        add(fieldsPanel, "growx, gaptop 10, gapbottom 5, wrap");
        refreshFieldsSectionsEnabled();
        add(panelSeparator(), MIG_FILL_WRAP);

        openSearchAuthFormPanel = buildAuthFormPanel();
        add(new ConfigDestinationPanel(
                fileSinkCheckbox,
                filePathField,
                fileJsonlCheckbox,
                fileBulkNdjsonCheckbox,
                buildFileLimitsPanel(),
                openSearchSinkCheckbox,
                openSearchUrlField,
                openSearchInsecureSslCheckbox,
                testConnectionButton,
                openSearchAuthFormPanel,
                openSearchStatus,
                openSearchStatusWrapper,
                INDENT,
                ROW_GAP,
                StatusViews::configureTextArea
        ).build(), "gaptop 10, gapbottom 5, wrap");

        wireButtonActions();
        add(panelSeparator(), MIG_FILL_WRAP);

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
                this::startExportAsync,
                () -> {
                    ExportReporterLifecycle.stopAndClearPendingExportWork();
                    Logger.logInfoPanelOnly("Export stopped.");
                }
        ).build(), MIG_FILL_WRAP);

        add(Box.createVerticalGlue(), "growy, wrap");

        assignComponentNames();
        wireTextFieldEnhancements();
        loadSessionOpenSearchCredentials();
        refreshEnabledStates();
        applyEditionRestrictions();
    }

    @Override
    public void addNotify() {
        super.addNotify();
        if (!scopeGridListenerRegistered) {
            scopeGrid.setOnContentChange(this::updateRuntimeConfig);
            scopeGridListenerRegistered = true;
        }
        if (!buttonStylesNormalized) {
            ButtonStyles.normalizeTree(this);
            buttonStylesNormalized = true;
        }
    }

    /** Loads in-memory auth values for the current Burp session. */
    private void loadSessionOpenSearchCredentials() {
        if (openSearchAuthTypeCombo == null) {
            return;
        }
        String selectedType = SecureCredentialStore.loadSelectedAuthType();
        if (selectedType == null || selectedType.isBlank() || "None".equals(selectedType)) {
            selectedType = "Basic";
        }
        openSearchAuthTypeCombo.setSelectedItem(selectedType);
        loadSessionAuthFields();
        updateRuntimeConfig();
    }

    /** Groups file-format radios and keeps one selection active for the UI/runtime state. */
    private void configureFileFormatButtons() {
        fileFormatGroup.add(fileJsonlCheckbox);
        fileFormatGroup.add(fileBulkNdjsonCheckbox);
        if (!fileJsonlCheckbox.isSelected() && !fileBulkNdjsonCheckbox.isSelected()) {
            fileBulkNdjsonCheckbox.setSelected(true);
        }
    }

    private void loadSessionAuthFields() {
        SecureCredentialStore.BasicCredentials basic = SecureCredentialStore.loadOpenSearchCredentials();
        openSearchUserField.setText(basic.username());
        openSearchPasswordField.setText(basic.password());

        SecureCredentialStore.ApiKeyCredentials apiKey = SecureCredentialStore.loadApiKeyCredentials();
        openSearchApiKeyIdField.setText(apiKey.keyId());
        openSearchApiKeySecretField.setText(apiKey.keySecret());

        SecureCredentialStore.JwtCredentials jwt = SecureCredentialStore.loadJwtCredentials();
        openSearchJwtTokenField.setText(jwt.token());

        SecureCredentialStore.CertificateCredentials cert = SecureCredentialStore.loadCertificateCredentials();
        openSearchCertPathField.setText(cert.certPath());
        openSearchCertKeyPathField.setText(cert.keyPath());
        openSearchCertPassphraseField.setText(cert.passphrase());
    }

    /**
     * Starts export without blocking the EDT.
     *
     * <p>Caller must invoke on the EDT. This method captures UI state, marks export running
     * immediately, then performs OpenSearch bootstrap and initial snapshot pushes on a background
     * executor. If bootstrap fails, runtime state and UI start/stop controls are reverted on EDT.</p>
     *
     * @param uiCallbacks callbacks from {@link ConfigControlPanel} to revert or complete Start UI state
     */
    private void startExportAsync(ConfigControlPanel.StartUiCallbacks uiCallbacks) {
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        if (fileSinkCheckbox.isSelected() && !hasSelectedFileFormat()) {
            Logger.logErrorPanelOnly("[Start] Files selected but no file format is enabled.");
            RuntimeConfig.setExportStarting(false);
            onControlStatus("Start aborted: select at least one file format when Files export is enabled.");
            uiCallbacks.onStartFailure().run();
            return;
        }
        RuntimeConfig.setExportStarting(true);
        persistSelectedAuthSecrets();
        updateRuntimeConfig();
        String url = openSearchUrlField.getText().trim();
        List<String> sources = List.copyOf(getSelectedSources());
        ExportStats.recordExportStartRequested();
        RuntimeConfig.setExportRunning(true);
        STARTUP_EXECUTOR.execute(() -> runStartupPipeline(url, sources, uiCallbacks));
    }

    /** Returns whether at least one file-export format checkbox is selected. */
    private boolean hasSelectedFileFormat() {
        return fileJsonlCheckbox.isSelected() || fileBulkNdjsonCheckbox.isSelected();
    }

    /**
     * Runs OpenSearch bootstrap and initial reporter startup on a background thread.
     *
     * <p>Not EDT-only. On bootstrap failure, this method posts revert work to EDT so UI state
     * remains consistent with runtime state.</p>
     *
     * @param url OpenSearch base URL from UI
     * @param sources selected source keys at Start time
     * @param uiCallbacks callbacks to revert or complete Start button/indicator state
     */
    private void runStartupPipeline(String url, List<String> sources, ConfigControlPanel.StartUiCallbacks uiCallbacks) {
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        boolean openSearchEnabled = RuntimeConfig.getState() != null
                && RuntimeConfig.getState().sinks() != null
                && RuntimeConfig.getState().sinks().osEnabled()
                && !url.isEmpty();
        if (RuntimeConfig.isAnyFileExportEnabled()) {
            try {
                String fileRoot = RuntimeConfig.fileExportRoot();
                Logger.logDebug("[Start] File export preflight for " + fileRoot);
                FileUtil.ensureDirectoryWritable(Path.of(fileRoot), "file export root");
            } catch (IOException | RuntimeException e) {
                String reason = e.getMessage() == null || e.getMessage().isBlank()
                        ? "File export preflight failed."
                        : "File export preflight failed: " + e.getMessage();
                if (!openSearchEnabled) {
                    ExportReporterLifecycle.stopAndClearPendingExportWork();
                    SwingUtilities.invokeLater(() -> {
                        onControlStatus("Start aborted: " + reason);
                        uiCallbacks.onStartFailure().run();
                    });
                    return;
                }
                FileExportService.disableCurrentRoot(reason + " OpenSearch export will continue.");
            }
        }
        if (openSearchEnabled && !url.isEmpty()) {
            Logger.logDebug("[Start] OpenSearch preflight test for " + url);
            var preflight = ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper.safeTestConnection(
                    url,
                    RuntimeConfig.openSearchUser(),
                    RuntimeConfig.openSearchPassword());
            Logger.logDebug("[Start] OpenSearch preflight result: success=" + preflight.success()
                    + ", message=" + preflight.message());
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!preflight.success()) {
                String reason = preflight.message() == null || preflight.message().isBlank()
                        ? "OpenSearch preflight failed."
                        : "OpenSearch preflight failed: " + preflight.message();
                ExportReporterLifecycle.stopAndClearPendingExportWork();
                SwingUtilities.invokeLater(() -> {
                    onControlStatus("Start aborted: " + reason);
                    uiCallbacks.onStartFailure().run();
                });
                return;
            }

            Logger.logDebug("[Start] Ensuring OpenSearch indexes for sources: " + sources);
            List<OpenSearchSink.IndexResult> results = OpenSearchSink.createSelectedIndexes(url, sources,
                    RuntimeConfig.openSearchUser(), RuntimeConfig.openSearchPassword(), RuntimeConfig::isExportRunning);
            for (OpenSearchSink.IndexResult r : results) {
                Logger.logDebug("[Start] Index " + r.fullName() + ": " + r.status()
                        + (r.error() != null ? " (" + r.error() + ")" : ""));
            }
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (results.stream().anyMatch(r -> r.status() == OpenSearchSink.IndexResult.Status.FAILED)) {
                Logger.logErrorPanelOnly("[Start] Ensure indexes: one or more failed; see log above.");
                ExportReporterLifecycle.stopAndClearPendingExportWork();
                SwingUtilities.invokeLater(() -> {
                    onControlStatus("Start aborted: one or more indexes failed to initialize.");
                    uiCallbacks.onStartFailure().run();
                });
                return;
            }
        }

        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        RuntimeConfig.setExportStarting(false);
        SwingUtilities.invokeLater(() -> uiCallbacks.onStartSuccess().run());
        ToolIndexConfigReporter.pushConfigSnapshot();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        ToolIndexStatsReporter.start();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        SettingsIndexReporter.pushSnapshotNow();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        SettingsIndexReporter.start();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        FindingsIndexReporter.start();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        FindingsIndexReporter.pushSnapshotNow();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        SitemapIndexReporter.start();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        SitemapIndexReporter.pushSnapshotNow();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        ProxyHistoryIndexReporter.pushSnapshotNow();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        ProxyWebSocketIndexReporter.start();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        ProxyWebSocketIndexReporter.pushSnapshotNow();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        Logger.logInfoPanelOnly("Export started.");
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
            Tooltips.apply(issuesCheckbox, Tooltips.html("Not available with Community license."));
        } else {
            issuesCheckbox.setEnabled(true);
            Tooltips.apply(issuesCheckbox, Tooltips.html("All findings (aka issues)."));
        }
    }

    /**
     * Creates a separator used between major configuration blocks.
     *
     * @return new separator component
     */
    private JComponent panelSeparator() { return new ThickSeparator(); }

    /* ----------------------- ConfigController.Ui ----------------------- */

    /** File-export runtime messages are routed through Config Control instead. */
    @Override public void onFileStatus(String message) { }

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
     * Updates the Control status area on the EDT.
     *
     * <p>
     * @param message status text to display (nullable)
     */
    @Override public void onControlStatus(String message) {
        Runnable r = () -> {
            StatusViews.setStatus(
                    controlStatus, controlStatusWrapper, message, STATUS_MIN_COLS, STATUS_MAX_COLS);
        };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else {
            try { SwingUtilities.invokeAndWait(r); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); SwingUtilities.invokeLater(r); }
            catch (InvocationTargetException ex) { SwingUtilities.invokeLater(r); }
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

            ConfigState.Sinks sinks = state.sinks();
            if (sinks != null) {
                fileSinkCheckbox.setSelected(sinks.filesEnabled());
                filePathField.setText(sinks.filesPath() != null ? sinks.filesPath() : "");
                applyFileFormatSelection(sinks.fileJsonlEnabled(), sinks.fileBulkNdjsonEnabled());
                fileTotalCapCheckbox.setSelected(sinks.fileTotalCapEnabled());
                fileTotalCapField.setText(formatGiBLimit(sinks.fileTotalCapBytes()));
                fileDiskUsagePercentCheckbox.setSelected(sinks.fileDiskUsagePercentEnabled());
                fileDiskUsagePercentField.setText(String.valueOf(sinks.fileDiskUsagePercent()));
                openSearchSinkCheckbox.setSelected(sinks.osEnabled());
                openSearchUrlField.setText(sinks.openSearchUrl() != null ? sinks.openSearchUrl() : "");
                openSearchInsecureSslCheckbox.setSelected(sinks.openSearchInsecureSsl());
            }

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

            applyExportFieldsState(state.enabledExportFieldsByIndex());
            refreshFieldsSectionsEnabled();
            refreshEnabledStates();
            updateRuntimeConfig();
        };
        runOnEdt(r);
    }

    /**
     * Applies one normalized file-format selection to the UI.
     *
     * <p>If both or neither are requested, {@code NDJSON} wins as the default selection.</p>
     */
    private void applyFileFormatSelection(boolean jsonlSelected, boolean bulkNdjsonSelected) {
        if (jsonlSelected == bulkNdjsonSelected) {
            fileBulkNdjsonCheckbox.setSelected(true);
            return;
        }
        fileJsonlCheckbox.setSelected(jsonlSelected);
        fileBulkNdjsonCheckbox.setSelected(bulkNdjsonSelected);
    }

    /** Applies imported enabled-export-fields state to Fields panel checkboxes; null = all selected. */
    private void applyExportFieldsState(java.util.Map<String, java.util.Set<String>> enabledByIndex) {
        if (fieldCheckboxesByIndex == null) return;
        for (String indexName : ai.attackframework.tools.burp.utils.config.ExportFieldRegistry.INDEX_ORDER) {
            java.util.Map<String, JCheckBox> checkboxes = fieldCheckboxesByIndex.get(indexName);
            if (checkboxes == null) continue;
            java.util.Set<String> enabled = enabledByIndex != null ? enabledByIndex.get(indexName) : null;
            for (java.util.Map.Entry<String, JCheckBox> e : checkboxes.entrySet()) {
                boolean select = enabled == null || enabled.contains(e.getKey());
                e.getValue().setSelected(select);
            }
        }
    }

    private void updateRuntimeConfig() {
        RuntimeConfig.updateState(buildCurrentState());
    }

    /** Grey-out and disable each Fields section when no related source option is selected; re-enable when at least one is selected. Does not change checkbox selected state. */
    private void refreshFieldsSectionsEnabled() {
        if (fieldsSectionHeaderRows == null || fieldsExpandButtons == null || fieldsSubPanels == null || fieldCheckboxesByIndex == null) return;
        for (String indexName : ai.attackframework.tools.burp.utils.config.ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            boolean enabled = isAnySourceOptionSelectedForFieldsIndex(indexName);
            JPanel headerRow = fieldsSectionHeaderRows.get(indexName);
            if (headerRow != null) {
                headerRow.setEnabled(enabled);
                for (java.awt.Component c : headerRow.getComponents()) c.setEnabled(enabled);
            }
            JButton expandBtn = fieldsExpandButtons.get(indexName);
            if (expandBtn != null) expandBtn.setEnabled(true); // keep expand/collapse always enabled
            JPanel sub = fieldsSubPanels.get(indexName);
            if (sub != null) sub.setEnabled(enabled);
            java.util.Map<String, JCheckBox> checkboxes = fieldCheckboxesByIndex.get(indexName);
            if (checkboxes != null) {
                for (JCheckBox cb : checkboxes.values()) cb.setEnabled(enabled);
            }
        }
    }

    /** True if at least one source option for this index is selected (so the Fields section should be enabled). Handles partial selection and parent-click timing: parent selected OR any child selected. */
    private boolean isAnySourceOptionSelectedForFieldsIndex(String indexName) {
        return switch (indexName) {
            case "settings" -> settingsCheckbox.isSelected() || settingsProjectCheckbox.isSelected() || settingsUserCheckbox.isSelected();
            case "sitemap" -> sitemapCheckbox.isSelected();
            case "findings" -> issuesCheckbox.isSelected() || issuesCriticalCheckbox.isSelected() || issuesHighCheckbox.isSelected()
                    || issuesMediumCheckbox.isSelected() || issuesLowCheckbox.isSelected() || issuesInformationalCheckbox.isSelected();
            case "traffic" -> trafficCheckbox.isSelected() || trafficBurpAiCheckbox.isSelected() || trafficExtensionsCheckbox.isSelected() || trafficIntruderCheckbox.isSelected()
                    || trafficProxyCheckbox.isSelected() || trafficProxyHistoryCheckbox.isSelected() || trafficRepeaterCheckbox.isSelected()
                    || trafficScannerCheckbox.isSelected() || trafficSequencerCheckbox.isSelected();
            default -> false;
        };
    }

    /* ----------------------------- Wiring ----------------------------- */

    /**
     * Wires button and checkbox actions for destination and layout relayout hooks.
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
        // Defer so checkbox model and other listeners run first, avoiding flakiness when toggling source
        ActionListener refreshFieldsSections = e -> SwingUtilities.invokeLater(this::refreshFieldsSectionsEnabled);
        settingsCheckbox.addActionListener(refreshFieldsSections);
        sitemapCheckbox.addActionListener(refreshFieldsSections);
        issuesCheckbox.addActionListener(refreshFieldsSections);
        trafficCheckbox.addActionListener(refreshFieldsSections);
        settingsProjectCheckbox.addActionListener(runtimeUpdater);
        settingsProjectCheckbox.addActionListener(refreshFieldsSections);
        settingsUserCheckbox.addActionListener(runtimeUpdater);
        settingsUserCheckbox.addActionListener(refreshFieldsSections);
        trafficBurpAiCheckbox.addActionListener(runtimeUpdater);
        trafficBurpAiCheckbox.addActionListener(refreshFieldsSections);
        trafficExtensionsCheckbox.addActionListener(runtimeUpdater);
        trafficExtensionsCheckbox.addActionListener(refreshFieldsSections);
        trafficIntruderCheckbox.addActionListener(runtimeUpdater);
        trafficIntruderCheckbox.addActionListener(refreshFieldsSections);
        trafficProxyCheckbox.addActionListener(runtimeUpdater);
        trafficProxyCheckbox.addActionListener(refreshFieldsSections);
        trafficProxyHistoryCheckbox.addActionListener(runtimeUpdater);
        trafficProxyHistoryCheckbox.addActionListener(refreshFieldsSections);
        trafficRepeaterCheckbox.addActionListener(runtimeUpdater);
        trafficRepeaterCheckbox.addActionListener(refreshFieldsSections);
        trafficScannerCheckbox.addActionListener(runtimeUpdater);
        trafficScannerCheckbox.addActionListener(refreshFieldsSections);
        trafficSequencerCheckbox.addActionListener(runtimeUpdater);
        trafficSequencerCheckbox.addActionListener(refreshFieldsSections);
        issuesCriticalCheckbox.addActionListener(runtimeUpdater);
        issuesCriticalCheckbox.addActionListener(refreshFieldsSections);
        issuesHighCheckbox.addActionListener(runtimeUpdater);
        issuesHighCheckbox.addActionListener(refreshFieldsSections);
        issuesMediumCheckbox.addActionListener(runtimeUpdater);
        issuesMediumCheckbox.addActionListener(refreshFieldsSections);
        issuesLowCheckbox.addActionListener(runtimeUpdater);
        issuesLowCheckbox.addActionListener(refreshFieldsSections);
        issuesInformationalCheckbox.addActionListener(runtimeUpdater);
        issuesInformationalCheckbox.addActionListener(refreshFieldsSections);

        allRadio.addActionListener(runtimeUpdater);
        burpSuiteRadio.addActionListener(runtimeUpdater);
        customRadio.addActionListener(runtimeUpdater);

        fileSinkCheckbox.addActionListener(sinkUpdater);
        fileJsonlCheckbox.addActionListener(sinkUpdater);
        fileBulkNdjsonCheckbox.addActionListener(sinkUpdater);
        fileTotalCapCheckbox.addActionListener(sinkUpdater);
        fileDiskUsagePercentCheckbox.addActionListener(sinkUpdater);
        openSearchSinkCheckbox.addActionListener(sinkUpdater);

        testConnectionButton.addActionListener(e -> {
            persistSelectedAuthSecrets();
            updateRuntimeConfig();
            String url = openSearchUrlField.getText().trim();
            if (url.isEmpty()) { onOpenSearchStatus("✖ URL required"); return; }
            onOpenSearchStatus("Testing ...");
            controller().testConnectionAsync(url);
        });
        openSearchPasswordField.addActionListener(e -> {
            String selectedType = openSearchAuthTypeCombo == null
                    ? "None"
                    : String.valueOf(openSearchAuthTypeCombo.getSelectedItem());
            if ("Basic".equals(selectedType) && openSearchPasswordField.isEnabled() && testConnectionButton.isEnabled()) {
                testConnectionButton.doClick();
            }
        });

        DocumentListener relayout = Doc.onChange(() -> {
            filePathField.revalidate();
            openSearchUrlField.revalidate();
            updateRuntimeConfig();
        });
        filePathField.getDocument().addDocumentListener(relayout);
        openSearchUrlField.getDocument().addDocumentListener(relayout);
        fileTotalCapField.getDocument().addDocumentListener(relayout);
        fileDiskUsagePercentField.getDocument().addDocumentListener(relayout);
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

    /** Builds inline OpenSearch authentication controls (auth type + type-specific credential fields). */
    private JPanel buildAuthFormPanel() {
        String[] authTypes = { "API Key", "Basic", "Certificate", "JWT", "None" };
        JComboBox<String> authTypeCombo = new Tooltips.HtmlComboBox<>(authTypes);
        openSearchAuthTypeCombo = authTypeCombo;
        authTypeCombo.setName("os.authType");
        authTypeCombo.setSelectedItem("Basic");
        String longest = java.util.Arrays.stream(authTypes).max(java.util.Comparator.comparingInt(String::length)).orElse("Certificate");
        authTypeCombo.setPrototypeDisplayValue(longest);

        JPanel contentCards = new JPanel(new MigLayout("insets 0, hidemode 3", "[left]", "[]"));
        contentCards.setName("os.authContent");

        JPanel noneCard = new JPanel(new MigLayout("insets 0", "[left]", "[]"));
        noneCard.setName("os.authCard.none");

        JPanel basicCard = new JPanel(new MigLayout("insets 0", "[pref][pref][pref][pref][pref]", "[]"));
        basicCard.setName("os.authCard.basic");
        basicCard.add(new JLabel("Username:"));
        basicCard.add(openSearchUserField, "gapright 15");
        basicCard.add(new JLabel("Password:"));
        basicCard.add(openSearchPasswordField, "gapright 15");

        JPanel apiKeyCard = new JPanel(new MigLayout("insets 0", "[pref][pref][pref][pref][pref]", "[]"));
        apiKeyCard.setName("os.authCard.apikey");
        apiKeyCard.add(new JLabel("Key ID:"));
        apiKeyCard.add(openSearchApiKeyIdField, "gapright 15");
        apiKeyCard.add(new JLabel("Key Secret:"));
        apiKeyCard.add(openSearchApiKeySecretField, "gapright 15");

        JPanel jwtCard = new JPanel(new MigLayout("insets 0", "[pref][pref][pref]", "[]"));
        jwtCard.setName("os.authCard.jwt");
        jwtCard.add(new JLabel("JWT Token:"));
        jwtCard.add(openSearchJwtTokenField, "w 360!");

        JPanel clientCertCard = new JPanel(new MigLayout("insets 0, wrap 2", "[pref][pref]", "[][][]"));
        clientCertCard.setName("os.authCard.certificate");
        clientCertCard.add(new JLabel("Cert Path:"));
        clientCertCard.add(openSearchCertPathField, "w 360!");
        clientCertCard.add(new JLabel("Key Path:"));
        clientCertCard.add(openSearchCertKeyPathField, "w 360!");
        clientCertCard.add(new JLabel("Passphrase:"));
        clientCertCard.add(openSearchCertPassphraseField, "w 360!");

        contentCards.add(noneCard, "hidemode 3");
        contentCards.add(basicCard, "hidemode 3");
        contentCards.add(apiKeyCard, "hidemode 3");
        contentCards.add(jwtCard, "hidemode 3");
        contentCards.add(clientCertCard, "hidemode 3");

        java.util.function.Consumer<String> applyAuthTypeCardVisibility = selectedType -> {
            noneCard.setVisible("None".equals(selectedType));
            basicCard.setVisible("Basic".equals(selectedType));
            apiKeyCard.setVisible("API Key".equals(selectedType));
            jwtCard.setVisible("JWT".equals(selectedType));
            clientCertCard.setVisible("Certificate".equals(selectedType));
        };

        authTypeCombo.addActionListener(e -> {
            String selectedType = String.valueOf(authTypeCombo.getSelectedItem());
            SecureCredentialStore.saveSelectedAuthType(selectedType);
            applyAuthTypeCardVisibility.accept(selectedType);
            updateRuntimeConfig();
            contentCards.revalidate();
            contentCards.repaint();
        });
        String selectedType = String.valueOf(authTypeCombo.getSelectedItem());
        applyAuthTypeCardVisibility.accept(selectedType);
        JPanel form = new JPanel(new MigLayout("insets 0", "[pref][pref][grow]", "[]"));
        form.setAlignmentX(Component.LEFT_ALIGNMENT);

        String authTypeTip = Tooltips.html("Select how requests to OpenSearch authenticate.");
        String basicUserTip = Tooltips.html("OpenSearch Basic auth username.", "Stored only within in-process memory.");
        String basicPasswordTip = Tooltips.html("OpenSearch Basic auth password.", "Stored only within in-process memory.");
        String apiKeyIdTip = Tooltips.html("OpenSearch API key ID.", "Stored only within in-process memory.");
        String apiKeySecretTip = Tooltips.html("OpenSearch API key secret.", "Stored only within in-process memory.");
        String jwtTip = Tooltips.html("OpenSearch JWT bearer token.", "Stored only within in-process memory.");
        String certPathTip = Tooltips.html("Path to the client certificate file used for OpenSearch authentication.");
        String keyPathTip = Tooltips.html("Path to the client private key file used for OpenSearch authentication.");
        String passphraseTip = Tooltips.html("Client key passphrase.", "Stored only within in-process memory.");

        Tooltips.apply(authTypeCombo, authTypeTip);
        Tooltips.apply(openSearchUserField, basicUserTip);
        Tooltips.apply(openSearchPasswordField, basicPasswordTip);
        Tooltips.apply(openSearchApiKeyIdField, apiKeyIdTip);
        Tooltips.apply(openSearchApiKeySecretField, apiKeySecretTip);
        Tooltips.apply(openSearchJwtTokenField, jwtTip);
        Tooltips.apply(openSearchCertPathField, certPathTip);
        Tooltips.apply(openSearchCertKeyPathField, keyPathTip);
        Tooltips.apply(openSearchCertPassphraseField, passphraseTip);

        basicCard.removeAll();
        basicCard.add(Tooltips.label("Username:", basicUserTip));
        basicCard.add(openSearchUserField, "gapright 15");
        basicCard.add(Tooltips.label("Password:", basicPasswordTip));
        basicCard.add(openSearchPasswordField, "gapright 15");

        apiKeyCard.removeAll();
        apiKeyCard.add(Tooltips.label("Key ID:", apiKeyIdTip));
        apiKeyCard.add(openSearchApiKeyIdField, "gapright 15");
        apiKeyCard.add(Tooltips.label("Key Secret:", apiKeySecretTip));
        apiKeyCard.add(openSearchApiKeySecretField, "gapright 15");

        jwtCard.removeAll();
        jwtCard.add(Tooltips.label("JWT Token:", jwtTip));
        jwtCard.add(openSearchJwtTokenField, "w 360!");

        clientCertCard.removeAll();
        clientCertCard.add(Tooltips.label("Cert Path:", certPathTip));
        clientCertCard.add(openSearchCertPathField, "w 360!");
        clientCertCard.add(Tooltips.label("Key Path:", keyPathTip));
        clientCertCard.add(openSearchCertKeyPathField, "w 360!");
        clientCertCard.add(Tooltips.label("Passphrase:", passphraseTip));
        clientCertCard.add(openSearchCertPassphraseField, "w 360!");

        form.add(Tooltips.label("Auth type:", authTypeTip));
        form.add(authTypeCombo);
        form.add(contentCards, "gapleft 15");

        return form;
    }

    /**
     * Caches auth values in memory for the current Burp session.
     */
    private void persistSelectedAuthSecrets() {
        String selectedType = openSearchAuthTypeCombo == null
                ? "None"
                : String.valueOf(openSearchAuthTypeCombo.getSelectedItem());
        SecureCredentialStore.saveSelectedAuthType(selectedType);
        switch (selectedType) {
            case "Basic" -> SecureCredentialStore.saveOpenSearchCredentials(
                    openSearchUserField.getText(),
                    passwordText(openSearchPasswordField));
            case "API Key" -> SecureCredentialStore.saveApiKeyCredentials(
                    openSearchApiKeyIdField.getText(),
                    passwordText(openSearchApiKeySecretField));
            case "JWT" -> SecureCredentialStore.saveJwtCredentials(openSearchJwtTokenField.getText());
            case "Certificate" -> SecureCredentialStore.saveCertificateCredentials(
                    openSearchCertPathField.getText(),
                    openSearchCertKeyPathField.getText(),
                    passwordText(openSearchCertPassphraseField));
            default -> { }
        }
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
        List<JCheckBox> safeChildren = children == null ? List.of() : children;
        java.util.concurrent.atomic.AtomicBoolean syncing = new java.util.concurrent.atomic.AtomicBoolean(false);

        Runnable syncParentFromChildren = () -> {
            if (safeChildren.isEmpty()) {
                return;
            }
            int selected = 0;
            for (JCheckBox c : safeChildren) {
                if (c.isSelected()) {
                    selected++;
                }
            }
            if (selected == 0) {
                parent.setState(TriStateCheckBox.State.DESELECTED);
            } else if (selected == safeChildren.size()) {
                parent.setState(TriStateCheckBox.State.SELECTED);
            } else {
                parent.setState(TriStateCheckBox.State.INDETERMINATE);
            }
        };

        for (JCheckBox child : safeChildren) {
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

        parent.addActionListener(e -> {
            if (syncing.get()) {
                return;
            }
            syncing.set(true);
            try {
                boolean selectAll = parent.getState() != TriStateCheckBox.State.DESELECTED;
                for (JCheckBox child : safeChildren) {
                    child.setSelected(selectAll);
                }
                syncParentFromChildren.run();
            } finally {
                syncing.set(false);
            }
        });

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
        fileJsonlCheckbox.setEnabled(files);
        fileBulkNdjsonCheckbox.setEnabled(files);
        fileTotalCapCheckbox.setEnabled(files);
        fileTotalCapField.setEnabled(files && fileTotalCapCheckbox.isSelected());
        fileDiskUsagePercentCheckbox.setEnabled(files);
        fileDiskUsagePercentField.setEnabled(files && fileDiskUsagePercentCheckbox.isSelected());

        boolean os = openSearchSinkCheckbox.isSelected();
        openSearchUrlField.setEnabled(os);
        openSearchInsecureSslCheckbox.setEnabled(os);
        testConnectionButton.setEnabled(os);
        if (openSearchAuthFormPanel != null) {
            setEnabledRecursively(openSearchAuthFormPanel, os);
        }
    }

    private static void setEnabledRecursively(Component c, boolean enabled) {
        c.setEnabled(enabled);
        if (c instanceof java.awt.Container container) {
            for (Component child : container.getComponents()) {
                setEnabledRecursively(child, enabled);
            }
        }
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
        TextFieldUndo.install(fileTotalCapField);
        TextFieldUndo.install(fileDiskUsagePercentField);
        openSearchUrlField.addActionListener(e -> testConnectionButton.doClick());
    }

    private JPanel buildFileLimitsPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, gapx 8, gapy 0, novisualpadding",
                "[left][40!][left][left][40!][left]", "[]"));
        panel.setOpaque(false);
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(fileTotalCapCheckbox);
        panel.add(fileTotalCapField, "w 40!");
        panel.add(new JLabel("GiB"), "gapright 12");
        panel.add(fileDiskUsagePercentCheckbox);
        panel.add(fileDiskUsagePercentField, "w 40!");
        panel.add(new JLabel("%"));
        return panel;
    }

    /** Returns {@code value} if non-null and non-blank, otherwise {@code fallback}. */
    private static String nonBlankOr(String value, String fallback) {
        return (value != null && !value.isBlank()) ? value.trim() : (fallback != null ? fallback : "");
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

        String authType = openSearchAuthTypeCombo != null
                ? String.valueOf(openSearchAuthTypeCombo.getSelectedItem())
                : "None";
        boolean authBasic = "Basic".equals(authType);
        String osUser = authBasic ? nonBlankOr(openSearchUserField.getText(), "") : "";
        String osPass = authBasic ? nonBlankOr(passwordText(openSearchPasswordField), "") : "";
        return new ConfigState.State(
                selectedSources,
                scopeType,
                custom,
                new ConfigState.Sinks(filesEnabled, filesRoot, fileJsonlCheckbox.isSelected(),
                        fileBulkNdjsonCheckbox.isSelected(),
                        fileTotalCapCheckbox.isSelected(), parseGiBLimit(fileTotalCapField.getText(),
                                ConfigState.DEFAULT_FILE_TOTAL_CAP_BYTES),
                        fileDiskUsagePercentCheckbox.isSelected(), parsePercentLimit(fileDiskUsagePercentField.getText(),
                                ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT),
                        osEnabled, osUrl,
                        osUser,
                        osPass,
                        openSearchInsecureSslCheckbox.isSelected()),
                settingsSub,
                trafficToolTypes,
                findingsSeverities,
                buildEnabledExportFieldsByIndex()
        );
    }

    /** Builds enabled export fields map from Fields panel checkboxes; null = all enabled (omit from JSON). */
    private java.util.Map<String, java.util.Set<String>> buildEnabledExportFieldsByIndex() {
        if (fieldCheckboxesByIndex == null) return null;
        java.util.Map<String, java.util.Set<String>> out = new java.util.LinkedHashMap<>();
        boolean allSelected = true;
        for (String indexName : ai.attackframework.tools.burp.utils.config.ExportFieldRegistry.INDEX_ORDER) {
            java.util.Map<String, JCheckBox> checkboxes = fieldCheckboxesByIndex.get(indexName);
            if (checkboxes == null) continue;
            java.util.Set<String> enabled = new java.util.LinkedHashSet<>();
            for (java.util.Map.Entry<String, JCheckBox> e : checkboxes.entrySet()) {
                if (e.getValue().isSelected()) {
                    enabled.add(e.getKey());
                } else {
                    allSelected = false;
                }
            }
            out.put(indexName, java.util.Collections.unmodifiableSet(enabled));
        }
        if (allSelected) return null;
        return java.util.Collections.unmodifiableMap(out);
    }

    /**
     * Parses a GiB limit from the UI, accepting decimal values such as {@code 0.5}.
     *
     * <p>Invalid, blank, or non-positive input falls back to {@code defaultBytes}. Fractional GiB
     * values are converted to bytes using half-up rounding so import/export round-trips remain
     * stable for user-entered values such as {@code 1.25}.</p>
     */
    private static long parseGiBLimit(String raw, long defaultBytes) {
        try {
            BigDecimal gib = new BigDecimal(nonBlankOr(raw, "").trim());
            if (gib.compareTo(BigDecimal.ZERO) <= 0) {
                return defaultBytes;
            }
            BigDecimal bytes = gib.multiply(GIB_BYTES_DECIMAL).setScale(0, RoundingMode.HALF_UP);
            long asLong = bytes.longValueExact();
            return asLong > 0 ? asLong : defaultBytes;
        } catch (RuntimeException e) {
            return defaultBytes;
        }
    }

    /** Formats a byte limit back to a trimmed GiB string suitable for the UI text fields. */
    private static String formatGiBLimit(long bytes) {
        if (bytes <= 0) {
            return "1";
        }
        return BigDecimal.valueOf(bytes)
                .divide(GIB_BYTES_DECIMAL, 3, RoundingMode.HALF_UP)
                .stripTrailingZeros()
                .toPlainString();
    }

    private static int parsePercentLimit(String raw, int defaultPercent) {
        try {
            return Math.clamp(Integer.parseInt(nonBlankOr(raw, "")), 1, 100);
        } catch (NumberFormatException e) {
            return defaultPercent;
        }
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
        controller().exportConfigAsync(out, json);
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
        controller().importConfigAsync(chooser.getSelectedFile().toPath());
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
        fileJsonlCheckbox.setName("files.format.jsonl");
        fileBulkNdjsonCheckbox.setName("files.format.bulkNdjson");
        fileTotalCapCheckbox.setName("files.limit.total.enable");
        fileTotalCapField.setName("files.limit.total.gib");
        fileDiskUsagePercentCheckbox.setName("files.limit.diskPercent.enable");
        fileDiskUsagePercentField.setName("files.limit.diskPercent.value");

        openSearchSinkCheckbox.setName("os.enable");
        openSearchUrlField.setName("os.url");
        testConnectionButton.setName("os.test");

        controlStatusWrapper.setName("control.statusWrapper");
        controlStatus.setName("control.status");
    }

    /**
     * Assigns tooltips for all ConfigPanel controls.
     *
     * <p>EDT only. Consolidated here to keep tooltip text consistent and discoverable.</p>
     */
    private void assignToolTips() {
        Tooltips.apply(settingsCheckbox, Tooltips.html("All settings."));
        Tooltips.apply(sitemapCheckbox, Tooltips.html("All in-scope sitemaps."));
        Tooltips.apply(issuesCheckbox, Tooltips.html("All findings (aka issues)."));
        Tooltips.apply(trafficCheckbox, Tooltips.html("All in-scope traffic."));
        Tooltips.apply(settingsExpandButton, Tooltips.html("Settings sub-options."));
        Tooltips.apply(issuesExpandButton, Tooltips.html("Issues sub-options."));
        Tooltips.apply(trafficExpandButton, Tooltips.html("Traffic sub-options."));
        Tooltips.apply(settingsProjectCheckbox, Tooltips.html("Project settings."));
        Tooltips.apply(settingsUserCheckbox, Tooltips.html("User settings."));
        Tooltips.apply(trafficBurpAiCheckbox, Tooltips.html("All in-scope traffic sent from Burp AI."));
        Tooltips.apply(trafficExtensionsCheckbox, Tooltips.html("All in-scope traffic sent from all other extensions."));
        Tooltips.apply(trafficIntruderCheckbox, Tooltips.html("All in-scope traffic sent from Intruder."));
        Tooltips.apply(trafficProxyCheckbox, Tooltips.html("All in-scope traffic sent from Proxy."));
        Tooltips.apply(trafficProxyHistoryCheckbox, Tooltips.html(
                "All in-scope traffic from Proxy History.",
                "This exports smart batches when Start is clicked.",
                "For ongoing or future traffic, select Proxy."
        ));
        Tooltips.apply(trafficRepeaterCheckbox, Tooltips.html("All in-scope traffic sent from Repeater."));
        Tooltips.apply(trafficScannerCheckbox, Tooltips.html("All in-scope traffic sent from Scanner."));
        Tooltips.apply(trafficSequencerCheckbox, Tooltips.html("All in-scope traffic sent from Sequencer."));

        Tooltips.apply(allRadio, Tooltips.html("Export all observed."));
        Tooltips.apply(burpSuiteRadio, Tooltips.html("Export Burp Suite's project scope."));
        Tooltips.apply(customRadio, Tooltips.html("Export custom scope."));

        Tooltips.apply(fileSinkCheckbox, Tooltips.html("Enable file-based export."));
        Tooltips.apply(filePathField, Tooltips.html("Root directory for generated files."));
        Tooltips.apply(fileJsonlCheckbox, Tooltips.html(
                "JSONL (JSON Lines): write one filtered JSON document per line.",
                "Each line is a standalone JSON object; there is no OpenSearch bulk action metadata.",
                "Best for local grep, line-by-line tooling, or simple downstream processing."
        ));
        Tooltips.apply(fileBulkNdjsonCheckbox, Tooltips.html(
                "NDJSON (Newline-Delimited JSON): write OpenSearch bulk-request lines.",
                "Each exported document is written as two lines: bulk action metadata, then the JSON document body.",
                "Best for later re-import with the OpenSearch {@code _bulk} API."
        ));
        Tooltips.apply(fileTotalCapCheckbox, Tooltips.html(
                "Stop all file export under the selected root when exporter-managed files reach the configured combined cap."
        ));
        Tooltips.apply(fileTotalCapField, Tooltips.html(
                "GiB cap across exporter-managed files in the selected root.",
                "OpenSearch export can continue after this cap is hit."
        ));
        Tooltips.apply(fileDiskUsagePercentCheckbox, Tooltips.html(
                "Optional advanced stop condition based on the destination volume's used percent."
        ));
        Tooltips.apply(fileDiskUsagePercentField, Tooltips.html(
                "Stop file export when the destination volume is at or above this used-percent threshold.",
                "This does not replace the built-in low-disk reserve."
        ));

        Tooltips.apply(openSearchSinkCheckbox, Tooltips.html("Enable OpenSearch export."));
        Tooltips.apply(openSearchUrlField, Tooltips.html("Base URL of the OpenSearch cluster."));
        openSearchInsecureSslCheckbox.setName("os.insecureSsl");
        Tooltips.apply(openSearchInsecureSslCheckbox, Tooltips.html(
                "Skip TLS certificate verification.",
                "Useful for self-signed certificates."
        ));
        Tooltips.apply(testConnectionButton, Tooltips.html(
                "Test connectivity.",
                "Secrets are only stored within in-process memory."
        ));
    }

    /**
     * Save button handler: applies current UI state to runtime immediately so
     * traffic and tool index use the new config (e.g. scope) without restarting
     * export; persists via controller; triggers one tool index stats push when
     * export is running so the next snapshot reflects the saved config.
     */
    private class ControlSaveButtonListener implements ActionListener {
        @Override public void actionPerformed(ActionEvent e) {
            persistSelectedAuthSecrets();
            updateRuntimeConfig();
            if (RuntimeConfig.isExportRunning()) {
                ToolIndexConfigReporter.pushConfigSnapshot();
                ToolIndexStatsReporter.pushSnapshotNow();
            }
            controller().saveAsync(buildCurrentState());
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

    private static String passwordText(JPasswordField field) {
        if (field == null || field.getPassword() == null) {
            return "";
        }
        return new String(field.getPassword());
    }

    private ConfigController controller() {
        if (controller == null) {
            controller = new ConfigController(this);
        }
        return controller;
    }

    /** Rebuild transient collaborators after deserialization. */
    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        this.controller = new ConfigController(this);
        ControlStatusBridge.register(this::onControlStatus);
    }

}
