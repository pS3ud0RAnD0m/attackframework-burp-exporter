package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.AbstractAction;
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
import javax.swing.KeyStroke;
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
import ai.attackframework.tools.burp.sinks.ExporterIndexConfigReporter;
import ai.attackframework.tools.burp.sinks.ExporterIndexStatsReporter;
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
import ai.attackframework.tools.burp.ui.text.ValidationIndicator;
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
import ai.attackframework.tools.burp.utils.opensearch.IndexingRetryCoordinator;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchTlsSupport;
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
    /** ActionMap key: Enter on the OpenSearch TLS mode combo runs Test Connection. */
    private static final String TLS_MODE_ENTER_TEST_CONNECTION = "os.tlsMode.enterTestConnection";
    private static final int STATUS_MIN_COLS = 20;
    private static final int STATUS_MAX_COLS = 200;
    /** Background executor for Start-path OpenSearch bootstrap work. */
    private static final ExecutorService STARTUP_EXECUTOR = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "attackframework-startup");
        t.setDaemon(true);
        return t;
    });

    private final TriStateCheckBox settingsCheckbox = new TriStateCheckBox("Settings", TriStateCheckBox.State.SELECTED);
    private final JCheckBox sitemapCheckbox  = new Tooltips.HtmlCheckBox("Sitemap",  true);
    private final TriStateCheckBox issuesCheckbox   = new TriStateCheckBox("Issues",   TriStateCheckBox.State.SELECTED);
    private final TriStateCheckBox trafficCheckbox  = new TriStateCheckBox("Traffic",  TriStateCheckBox.State.SELECTED);
    private final TriStateCheckBox exporterCheckbox = new TriStateCheckBox("Exporter", TriStateCheckBox.State.SELECTED);

    private final JCheckBox settingsProjectCheckbox = new Tooltips.HtmlCheckBox("Project", true);
    private final JCheckBox settingsUserCheckbox    = new Tooltips.HtmlCheckBox("User", true);

    private final JCheckBox trafficBurpAiCheckbox       = new Tooltips.HtmlCheckBox("Burp AI", true);
    private final JCheckBox trafficExtensionsCheckbox   = new Tooltips.HtmlCheckBox("Extensions", true);
    private final JCheckBox trafficIntruderCheckbox    = new Tooltips.HtmlCheckBox("Intruder", true);
    private final JCheckBox trafficProxyCheckbox        = new Tooltips.HtmlCheckBox("Proxy", true);
    private final JCheckBox trafficProxyHistoryCheckbox  = new Tooltips.HtmlCheckBox("Proxy History", true);
    private final JCheckBox trafficRepeaterCheckbox    = new Tooltips.HtmlCheckBox("Repeater", true);
    private final JCheckBox trafficScannerCheckbox      = new Tooltips.HtmlCheckBox("Scanner", true);
    private final JCheckBox trafficSequencerCheckbox     = new Tooltips.HtmlCheckBox("Sequencer", true);

    private final JCheckBox issuesCriticalCheckbox      = new Tooltips.HtmlCheckBox("Critical", true);
    private final JCheckBox issuesHighCheckbox          = new Tooltips.HtmlCheckBox("High", true);
    private final JCheckBox issuesMediumCheckbox        = new Tooltips.HtmlCheckBox("Medium", true);
    private final JCheckBox issuesLowCheckbox           = new Tooltips.HtmlCheckBox("Low", true);
    private final JCheckBox issuesInformationalCheckbox = new Tooltips.HtmlCheckBox("Informational", true);

    private final JCheckBox exporterTraceCheckbox  = new Tooltips.HtmlCheckBox("Trace", true);
    private final JCheckBox exporterDebugCheckbox  = new Tooltips.HtmlCheckBox("Debug", true);
    private final JCheckBox exporterInfoCheckbox   = new Tooltips.HtmlCheckBox("Info", true);
    private final JCheckBox exporterWarnCheckbox   = new Tooltips.HtmlCheckBox("Warn", true);
    private final JCheckBox exporterErrorCheckbox  = new Tooltips.HtmlCheckBox("Error", true);
    private final JCheckBox exporterStatsCheckbox  = new Tooltips.HtmlCheckBox("Stats", true);
    private final JCheckBox exporterConfigCheckbox = new Tooltips.HtmlCheckBox("Config", true);
    private final JTextField exporterStatsIntervalField = new AutoSizingTextField(
            String.valueOf(ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS));
    private final JTextField indexNameBaseTemplateField = new AutoSizingTextField(
            ConfigState.DEFAULT_INDEX_NAME_BASE_TEMPLATE);
    private final JLabel indexNameBaseValidationIndicator = new Tooltips.HtmlLabel("");

    private static final String EXPAND_COLLAPSED = "+";
    private static final String EXPAND_EXPANDED = "−";
    private final JButton settingsExpandButton = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
    private final JButton issuesExpandButton   = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
    private final JButton trafficExpandButton  = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
    private final JButton exporterExpandButton = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
    private final JPanel issuesCommunityIndicator = ConfigSourcesPanel.buildCommunityEditionIndicator(
            "src.issues.communityNotice",
            "src.issues.communityNotice.icon");
    private final JPanel trafficBurpAiCommunityIndicator = ConfigSourcesPanel.buildCommunityEditionIndicator(
            "src.traffic.burp_ai.communityNotice",
            "src.traffic.burp_ai.communityNotice.icon");
    private final JPanel trafficScannerCommunityIndicator = ConfigSourcesPanel.buildCommunityEditionIndicator(
            "src.traffic.scanner.communityNotice",
            "src.traffic.scanner.communityNotice.icon");

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
    private final JCheckBox fileTotalCapCheckbox = new Tooltips.HtmlCheckBox("", true);
    private final JTextField fileTotalCapField = new AutoSizingTextField("10");
    private final JCheckBox fileDiskUsagePercentCheckbox = new Tooltips.HtmlCheckBox("", true);
    private final JTextField fileDiskUsagePercentField = new AutoSizingTextField("95");

    private final JCheckBox  openSearchSinkCheckbox = new Tooltips.HtmlCheckBox("OpenSearch", true);
    private final JTextField openSearchUrlField     = new AutoSizingTextField("https://opensearch.url:9200");
    private final JComboBox<String> openSearchTlsModeCombo = new Tooltips.HtmlComboBox<>(
            new String[] { "Verify", "Trust pinned certificate", "Trust all certificates" });
    private final JButton    importPinnedCertificateButton = new Tooltips.HtmlButton("Import Certificate");
    private final JButton    testConnectionButton   = new Tooltips.HtmlButton("Test Connection");
    /** OpenSearch auth controls panel (inline on the OpenSearch row). Built in {@link #buildAuthFormPanel()}. */
    private JPanel           openSearchAuthFormPanel;
    /** TLS controls panel (inline on the OpenSearch row). Built in {@link #buildTlsPanel()}. */
    private JPanel           openSearchTlsPanel;
    /** Last TLS mode logged to avoid duplicate mode-change messages during no-op selections. */
    private String           lastLoggedTlsMode = ConfigState.OPEN_SEARCH_TLS_VERIFY;
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
    private transient boolean suppressAuthSync;

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
    /** Creates the panel with its default controller. Caller must invoke on the EDT. */
    public ConfigPanel() { this(null); }

    /** Dependency-injected constructor (tests). */
    public ConfigPanel(ConfigController injectedController) {
        this.controller = injectedController;
        ControlStatusBridge.register(this::onControlStatus);

        setLayout(new MigLayout("fillx, insets 12", "[fill]"));

        assignToolTips();
        configureFileFormatButtons();
        configureIndexNameBaseValidationUi();

        ButtonStyles.configureExpandButton(settingsExpandButton);
        ButtonStyles.configureExpandButton(issuesExpandButton);
        ButtonStyles.configureExpandButton(trafficExpandButton);
        ButtonStyles.configureExpandButton(exporterExpandButton);

        JPanel settingsSubPanel = buildSettingsSubPanel();
        JPanel issuesSubPanel = buildIssuesSubPanel();
        JPanel trafficSubPanel = buildTrafficSubPanel();
        JPanel exporterSubPanel = buildExporterSubPanel();
        settingsSubPanel.setOpaque(false);
        issuesSubPanel.setOpaque(false);
        trafficSubPanel.setOpaque(false);
        exporterSubPanel.setOpaque(false);
        settingsSubPanel.setVisible(false);
        issuesSubPanel.setVisible(false);
        trafficSubPanel.setVisible(false);
        exporterSubPanel.setVisible(false);
        wireSourcesExpandCollapse(settingsExpandButton, settingsSubPanel);
        wireSourcesExpandCollapse(issuesExpandButton, issuesSubPanel);
        wireSourcesExpandCollapse(trafficExpandButton, trafficSubPanel);
        wireSourcesExpandCollapse(exporterExpandButton, exporterSubPanel);

        wireTriStateParentChild(settingsCheckbox, java.util.List.of(settingsProjectCheckbox, settingsUserCheckbox));
        wireTriStateParentChild(issuesCheckbox, java.util.List.of(
                issuesCriticalCheckbox, issuesHighCheckbox, issuesMediumCheckbox, issuesLowCheckbox, issuesInformationalCheckbox));
        wireTriStateParentChild(trafficCheckbox, java.util.List.of(
                trafficBurpAiCheckbox, trafficExtensionsCheckbox, trafficIntruderCheckbox, trafficProxyCheckbox,
                trafficProxyHistoryCheckbox, trafficRepeaterCheckbox, trafficScannerCheckbox, trafficSequencerCheckbox));
        wireTriStateParentChild(exporterCheckbox, java.util.List.of(
                exporterTraceCheckbox, exporterDebugCheckbox, exporterInfoCheckbox, exporterWarnCheckbox,
                exporterErrorCheckbox, exporterStatsCheckbox, exporterConfigCheckbox));

        add(new ConfigSourcesPanel(settingsCheckbox, sitemapCheckbox, issuesCheckbox, trafficCheckbox, exporterCheckbox,
                settingsExpandButton, settingsSubPanel, issuesExpandButton, issuesSubPanel,
                trafficExpandButton, trafficSubPanel, exporterExpandButton, exporterSubPanel,
                issuesCommunityIndicator, INDENT).build(),
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
            JPanel sub = new JPanel(new MigLayout("insets 0, wrap 1, hidemode 3", "[grow,left]"));
            sub.setOpaque(false);
            JPanel fieldsGrid = new JPanel(new MigLayout("insets 0, wrap 3", "[left][left][left]"));
            fieldsGrid.setOpaque(false);
            for (JCheckBox cb : perIndex.values()) {
                fieldsGrid.add(cb, "gapright 12");
            }
            sub.add(fieldsGrid, "growx, wrap");
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
        JPanel fieldsPanel = new ConfigFieldsPanel(
                fieldsExpandButtons,
                fieldsSubPanels,
                buildGlobalIndexNamingPanel(),
                INDENT).build(fieldsSectionHeaderRows);

        add(new ConfigScopePanel(allRadio, burpSuiteRadio, customRadio, scopeGrid, INDENT).build(),
                "gaptop 10, gapbottom 5, wrap");
        add(panelSeparator(), MIG_FILL_WRAP);

        add(fieldsPanel, "growx, gaptop 10, gapbottom 5, wrap");
        refreshFieldsSectionsEnabled();
        add(panelSeparator(), MIG_FILL_WRAP);

        openSearchAuthFormPanel = buildAuthFormPanel();
        openSearchTlsPanel = buildTlsPanel();
        add(new ConfigDestinationPanel(
                fileSinkCheckbox,
                filePathField,
                fileJsonlCheckbox,
                fileBulkNdjsonCheckbox,
                buildFileLimitsPanel(),
                openSearchSinkCheckbox,
                openSearchUrlField,
                openSearchTlsPanel,
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
                this::startExportAsync,
                () -> {
                    ExportReporterLifecycle.stopAndClearPendingExportWork();
                    Logger.logInfoPanelOnly("[Export] Stopped.");
                }
        ).build(), MIG_FILL_WRAP);

        add(Box.createVerticalGlue(), "growy, wrap");

        assignToolTips();
        assignComponentNames();
        wireTextFieldEnhancements();
        loadSessionOpenSearchCredentials();
        refreshEnabledStates();
        applyEditionRestrictions();
        refreshIndexNameBaseValidationState();
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
        if (selectedType == null || selectedType.isBlank() || "none".equalsIgnoreCase(selectedType)) {
            selectedType = "Basic";
        }
        suppressAuthSync = true;
        try {
            openSearchAuthTypeCombo.setSelectedItem(selectedType);
            loadSessionAuthFields();
        } finally {
            suppressAuthSync = false;
        }
        syncSelectedAuthStateFromUi();
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
        syncSelectedAuthStateFromUi();
        ai.attackframework.tools.burp.utils.IndexNaming.ResolutionResult indexNamingResolution =
                RuntimeConfig.prepareIndexNamesForCurrentRun();
        if (!indexNamingResolution.valid()) {
            abortStartOnEdt("fix index naming before Start: " + String.join(" ", indexNamingResolution.errors()), uiCallbacks);
            return;
        }
        boolean filesSelected = fileSinkCheckbox.isSelected();
        boolean openSearchSelected = openSearchSinkCheckbox.isSelected();
        if (fileSinkCheckbox.isSelected() && !hasSelectedFileFormat()) {
            abortStartOnEdt(
                    "select at least one file format when Files export is enabled.",
                    uiCallbacks);
            return;
        }
        List<String> startupIssues = validateSelectedDestinationConfiguration();
        if (!RuntimeConfig.isAnySinkEnabled()) {
            String reason = startupIssues.isEmpty()
                    ? "configure at least one destination."
                    : String.join(" ", startupIssues);
            abortStartOnEdt(reason, uiCallbacks);
            return;
        }
        RuntimeConfig.setExportStarting(true);
        String url = openSearchUrlField.getText().trim();
        List<String> sources = List.copyOf(getSelectedSources());
        ExportStats.recordExportStartRequested();
        Logger.logInfoPanelOnly("[Export] Starting. Selected destinations: "
                + summarizeSelectedDestinations(filesSelected, openSearchSelected) + ".");
        RuntimeConfig.setExportRunning(true);
        STARTUP_EXECUTOR.execute(() -> runStartupPipeline(
                url, sources, uiCallbacks, startupIssues, filesSelected, openSearchSelected));
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
    private void runStartupPipeline(
            String url,
            List<String> sources,
            ConfigControlPanel.StartUiCallbacks uiCallbacks,
            List<String> startupIssues,
            boolean filesSelected,
            boolean openSearchSelected
    ) {
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        List<String> runtimeStartIssues = new ArrayList<>(startupIssues);
        boolean openSearchEnabled = RuntimeConfig.getState() != null
                && RuntimeConfig.getState().sinks() != null
                && RuntimeConfig.getState().sinks().osEnabled()
                && !url.isEmpty();
        if (RuntimeConfig.isAnyFileExportEnabled()) {
            try {
                String fileRoot = RuntimeConfig.fileExportRoot();
                Logger.logDebug("[Files] Preflight check for " + fileRoot);
                Path fileRootPath = FileUtil.requireAbsoluteDirectoryPath(fileRoot);
                FileUtil.ensureDirectoryWritable(fileRootPath, "file export root");
                Logger.logInfoPanelOnly("[Files] Initializing files for selected sources.");
                Logger.logDebug("[Files] Ensuring files for sources: " + sources);
                List<FileExportService.FileInitResult> fileResults =
                        FileExportService.createSelectedExportFiles(sources, RuntimeConfig::isExportRunning);
                for (FileExportService.FileInitResult result : fileResults) {
                    Logger.logDebug("[Files] File "
                            + (result.path() != null ? result.path().getFileName() : result.shortName())
                            + ": " + result.status()
                            + (result.error() != null ? " (" + result.error() + ")" : ""));
                }
                if (fileResults.stream().anyMatch(r -> r.status() == FileUtil.Status.FAILED)) {
                    String reason = "one or more export files failed to initialize.";
                    logFileInitializationFailures(fileResults);
                    if (!openSearchEnabled) {
                        ExportReporterLifecycle.stopAndClearPendingExportWork();
                        abortStartFromWorker(reason, uiCallbacks);
                        return;
                    }
                    recordStartIssue(runtimeStartIssues, "Files failed during start: " + reason);
                    FileExportService.disableCurrentRoot("File export initialization failed. OpenSearch export will continue.");
                }
            } catch (IOException | RuntimeException e) {
                String reason = e.getMessage() == null || e.getMessage().isBlank()
                        ? "File export preflight failed."
                        : "File export preflight failed: " + e.getMessage();
                if (!openSearchEnabled) {
                    ExportReporterLifecycle.stopAndClearPendingExportWork();
                    abortStartFromWorker(reason, uiCallbacks);
                    return;
                }
                recordStartIssue(runtimeStartIssues, "Files failed during start: " + reason);
                FileExportService.disableCurrentRoot(reason + " OpenSearch export will continue.");
            }
        }
        if (openSearchEnabled && !url.isEmpty()) {
            Logger.logDebug("[OpenSearch] Preflight connection test for " + url);
            var preflight = ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper.safeTestConnection(
                    url,
                    RuntimeConfig.openSearchUser(),
                    RuntimeConfig.openSearchPassword());
            Logger.logDebug("[OpenSearch] Preflight result: success=" + preflight.success()
                    + ", message=" + preflight.message());
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!preflight.success()) {
                String reason = preflight.message() == null || preflight.message().isBlank()
                        ? "OpenSearch preflight failed."
                        : "OpenSearch preflight failed: " + preflight.message();
                if (!RuntimeConfig.isAnyFileExportEnabled()) {
                    ExportReporterLifecycle.stopAndClearPendingExportWork();
                    abortStartFromWorker(reason, uiCallbacks);
                    return;
                }
                recordStartIssue(runtimeStartIssues, "OpenSearch failed during start: " + reason);
                disableOpenSearchForCurrentRun(reason + " Files export will continue.");
                openSearchEnabled = false;
            }

            if (openSearchEnabled) {
                Logger.logInfoPanelOnly("[OpenSearch] Initializing indexes for selected sources.");
                Logger.logDebug("[OpenSearch] Ensuring indexes for sources: " + sources);
                List<OpenSearchSink.IndexResult> results = OpenSearchSink.createSelectedIndexes(url, sources,
                        RuntimeConfig.openSearchUser(), RuntimeConfig.openSearchPassword(), RuntimeConfig::isExportRunning);
                for (OpenSearchSink.IndexResult r : results) {
                    Logger.logDebug("[OpenSearch] Index " + r.fullName() + ": " + r.status()
                            + (r.error() != null ? " (" + r.error() + ")" : ""));
                }
                if (!RuntimeConfig.isExportRunning()) {
                    return;
                }
                if (results.stream().anyMatch(r -> r.status() == OpenSearchSink.IndexResult.Status.FAILED)) {
                    String reason = "one or more OpenSearch indexes failed to initialize.";
                    logOpenSearchIndexInitializationFailures(results);
                    if (!RuntimeConfig.isAnyFileExportEnabled()) {
                        ExportReporterLifecycle.stopAndClearPendingExportWork();
                        abortStartFromWorker(reason, uiCallbacks);
                        return;
                    }
                    recordStartIssue(
                            runtimeStartIssues,
                            "OpenSearch failed during start: " + reason);
                    disableOpenSearchForCurrentRun("OpenSearch index initialization failed. Files export will continue.");
                }
            }
        }

        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        RuntimeConfig.setExportStarting(false);
        String runningStatus = buildRunningStatusMessage(runtimeStartIssues, filesSelected, openSearchSelected);
        SwingUtilities.invokeLater(() -> {
            uiCallbacks.onStartSuccess().run();
            onControlStatus(runningStatus);
        });
        if (RuntimeConfig.isAnySinkEnabled()) {
            ExporterIndexConfigReporter.pushConfigSnapshot();
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            ExporterIndexStatsReporter.start();
        }
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
        Logger.logInfoPanelOnly("[Export] Started. Destinations: " + RuntimeConfig.activeSinkSummary() + ".");
    }

    private void disableOpenSearchForCurrentRun(String reason) {
        if (RuntimeConfig.disableOpenSearchDestination()) {
            IndexingRetryCoordinator.getInstance().clearPendingWork();
            Logger.logErrorPanelOnly("[OpenSearch] " + reason);
        }
    }

    private List<String> validateSelectedDestinationConfiguration() {
        List<String> startupIssues = new ArrayList<>();
        if (fileSinkCheckbox.isSelected() && filePathField.getText().trim().isEmpty()) {
            recordStartIssue(startupIssues, "Files not started: root directory is blank.");
        }
        if (openSearchSinkCheckbox.isSelected() && openSearchUrlField.getText().trim().isEmpty()) {
            recordStartIssue(startupIssues, "OpenSearch not started: base URL is blank.");
        }
        return startupIssues;
    }

    private void recordStartIssue(List<String> startupIssues, String issue) {
        startupIssues.add(issue);
        Logger.logErrorPanelOnly("[Export] " + issue);
    }

    private void abortStartOnEdt(String reason, ConfigControlPanel.StartUiCallbacks uiCallbacks) {
        Logger.logErrorPanelOnly("[Export] Start aborted: " + reason);
        RuntimeConfig.setExportStarting(false);
        onControlStatus("Start aborted: " + reason);
        uiCallbacks.onStartFailure().run();
    }

    private void abortStartFromWorker(String reason, ConfigControlPanel.StartUiCallbacks uiCallbacks) {
        Logger.logErrorPanelOnly("[Export] Start aborted: " + reason);
        RuntimeConfig.setExportStarting(false);
        SwingUtilities.invokeLater(() -> {
            onControlStatus("Start aborted: " + reason);
            uiCallbacks.onStartFailure().run();
        });
    }

    private static String summarizeSelectedDestinations(boolean filesSelected, boolean openSearchSelected) {
        if (filesSelected && openSearchSelected) {
            return "Files and OpenSearch";
        }
        if (filesSelected) {
            return "Files";
        }
        if (openSearchSelected) {
            return "OpenSearch";
        }
        return "none";
    }

    private static void logOpenSearchIndexInitializationFailures(List<OpenSearchSink.IndexResult> results) {
        Logger.logErrorPanelOnly("[OpenSearch] Index initialization failed for one or more selected indexes.");
        if (results == null) {
            return;
        }
        for (OpenSearchSink.IndexResult result : results) {
            if (result == null || result.status() != OpenSearchSink.IndexResult.Status.FAILED) {
                continue;
            }
            String detail = result.error() == null || result.error().isBlank() ? "unknown error" : result.error();
            Logger.logErrorPanelOnly("[OpenSearch] Index initialization failed for "
                    + result.fullName() + ": " + detail);
        }
    }

    private static void logFileInitializationFailures(List<FileExportService.FileInitResult> results) {
        Logger.logErrorPanelOnly("[Files] Export file initialization failed for one or more selected files.");
        if (results == null) {
            return;
        }
        for (FileExportService.FileInitResult result : results) {
            if (result == null || result.status() != FileUtil.Status.FAILED) {
                continue;
            }
            String detail = result.error() == null || result.error().isBlank() ? "unknown error" : result.error();
            String path = result.path() == null ? result.shortName() + result.format() : result.path().toString();
            Logger.logErrorPanelOnly("[Files] Export file initialization failed for " + path + ": " + detail);
        }
    }

    private static String buildRunningStatusMessage(
            List<String> startupIssues,
            boolean filesSelected,
            boolean openSearchSelected
    ) {
        String filesStatus = filesSelected
                ? (RuntimeConfig.isAnyFileExportEnabled()
                ? "Running -> " + activeFilesDestination()
                : "Not running")
                : null;
        String openSearchStatus = openSearchSelected
                ? (RuntimeConfig.isOpenSearchExportEnabled()
                ? "Running -> " + activeOpenSearchDestination()
                : "Not running")
                : null;
        if (startupIssues != null) {
            for (String issue : startupIssues) {
                if (issue == null || issue.isBlank()) {
                    continue;
                }
                if (issue.startsWith("Files not started: ")) {
                    filesStatus = "Not started (" + shortStatusDetail(issue.substring("Files not started: ".length())) + ")";
                } else if (issue.startsWith("OpenSearch not started: ")) {
                    openSearchStatus = "Not started (" + shortStatusDetail(issue.substring("OpenSearch not started: ".length())) + ")";
                } else if (issue.startsWith("Files failed during start: ")) {
                    filesStatus = "Start failed (" + shortStatusDetail(issue.substring("Files failed during start: ".length())) + ")";
                } else if (issue.startsWith("OpenSearch failed during start: ")) {
                    openSearchStatus = "Start failed (" + shortStatusDetail(issue.substring("OpenSearch failed during start: ".length())) + ")";
                }
            }
        }
        return buildDestinationStatusMessage(filesStatus, openSearchStatus);
    }

    private static String formatControlStatusMessage(String message) {
        if (message == null || message.isBlank()) {
            return message;
        }
        if (message.startsWith("OpenSearch export disabled after repeated ")
                && message.endsWith(" Files export will continue.")) {
            String detail = message.substring(
                    "OpenSearch export disabled after repeated ".length(),
                    message.length() - " Files export will continue.".length());
            return buildDestinationStatusMessage("Running", "Stopped (" + shortStatusDetail(detail) + ")");
        }
        if (message.startsWith("File export stopped: ")
                && message.endsWith(" OpenSearch export continues.")) {
            String detail = message.substring(
                    "File export stopped: ".length(),
                    message.length() - " OpenSearch export continues.".length());
            return buildDestinationStatusMessage("Stopped (" + shortStatusDetail(detail) + ")", "Running");
        }
        if (message.startsWith("Local disk writes stopped")
                && message.endsWith("OpenSearch export continues.")) {
            return buildDestinationStatusMessage("Stopped (" + shortStatusDetail(message) + ")", "Running");
        }
        return message;
    }

    private static String buildDestinationStatusMessage(String filesStatus, String openSearchStatus) {
        List<String> lines = new ArrayList<>(2);
        if (filesStatus != null && !filesStatus.isBlank()) {
            lines.add("Files: " + filesStatus);
        }
        if (openSearchStatus != null && !openSearchStatus.isBlank()) {
            lines.add("OpenSearch: " + openSearchStatus);
        }
        return lines.isEmpty() ? "Running" : String.join("\n", lines);
    }

    private static String shortStatusDetail(String detail) {
        if (detail == null || detail.isBlank()) {
            return "unknown error";
        }
        String shortened = detail.trim();
        shortened = shortened.replaceFirst("^OpenSearch preflight failed:\\s*", "");
        shortened = shortened.replaceFirst("^File export preflight failed:\\s*", "");
        shortened = shortened.replaceFirst("^OpenSearch index initialization failed\\.\\s*", "");
        shortened = shortened.replaceFirst("^(?:(?:[a-zA-Z_$][\\w$]*\\.)+[A-Za-z_$][\\w$]*Exception:\\s*)+", "");
        if (shortened.length() > 180) {
            shortened = shortened.substring(0, 177) + "...";
        }
        return shortened;
    }

    private static String activeFilesDestination() {
        String fileRoot = RuntimeConfig.fileExportRoot();
        if (fileRoot == null || fileRoot.isBlank()) {
            return "(path unavailable)";
        }
        try {
            return FileUtil.requireAbsoluteDirectoryPath(fileRoot).toString();
        } catch (IOException e) {
            return fileRoot.trim();
        }
    }

    private static String activeOpenSearchDestination() {
        String url = RuntimeConfig.openSearchUrl();
        return (url == null || url.isBlank()) ? "(url unavailable)" : url.trim();
    }

    /**
     * Applies Burp edition-specific source availability and Community-only tooltip overrides.
     *
     * <p>Community edition forces Findings off and disables the Burp AI and Scanner traffic
     * tool-type checkboxes. Professional re-enables those controls and hides the inline Community
     * notices.</p>
     */
    private void applyEditionRestrictions() {
        boolean communityEdition = isCommunityEdition();

        issuesCheckbox.setEnabled(!communityEdition);
        issuesExpandButton.setEnabled(!communityEdition);
        Tooltips.apply(issuesCheckbox, communityEdition
                ? Tooltips.html("Unsupported in Community Edition.")
                : Tooltips.html("All findings (aka issues)."));
        issuesCommunityIndicator.setVisible(communityEdition);
        if (communityEdition) {
            issuesCheckbox.setSelected(false);
            for (JCheckBox checkbox : issueSeverityCheckboxes()) {
                checkbox.setSelected(false);
                checkbox.setEnabled(false);
            }
            for (JCheckBox checkbox : findingsFieldCheckboxes()) {
                checkbox.setSelected(false);
                checkbox.setEnabled(false);
            }
        } else {
            for (JCheckBox checkbox : issueSeverityCheckboxes()) {
                checkbox.setEnabled(true);
            }
            for (JCheckBox checkbox : findingsFieldCheckboxes()) {
                checkbox.setEnabled(true);
            }
        }

        for (JCheckBox checkbox : communityLimitedTrafficCheckboxes()) {
            checkbox.setEnabled(!communityEdition);
            if (communityEdition) {
                checkbox.setSelected(false);
            }
        }
        for (JPanel indicator : communityLimitedTrafficIndicators()) {
            indicator.setVisible(communityEdition);
        }

        refreshFieldsSectionsEnabled();
        updateRuntimeConfig();
    }

    private boolean isCommunityEdition() {
        try {
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null || api.burpSuite() == null) {
                return false;
            }
            var version = api.burpSuite().version();
            return version != null && version.edition() == BurpSuiteEdition.COMMUNITY_EDITION;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private List<JCheckBox> issueSeverityCheckboxes() {
        return List.of(
                issuesCriticalCheckbox,
                issuesHighCheckbox,
                issuesMediumCheckbox,
                issuesLowCheckbox,
                issuesInformationalCheckbox);
    }

    private List<JCheckBox> findingsFieldCheckboxes() {
        if (fieldCheckboxesByIndex == null) {
            return List.of();
        }
        java.util.Map<String, JCheckBox> findings = fieldCheckboxesByIndex.get("findings");
        return findings == null ? List.of() : List.copyOf(findings.values());
    }

    private List<JCheckBox> communityLimitedTrafficCheckboxes() {
        return List.of(trafficBurpAiCheckbox, trafficScannerCheckbox);
    }

    private List<JPanel> communityLimitedTrafficIndicators() {
        return List.of(trafficBurpAiCommunityIndicator, trafficScannerCommunityIndicator);
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
     * @param message status text to display (nullable)
     */
    @Override public void onOpenSearchStatus(String message) {
        StatusViews.setStatus(
                openSearchStatus, openSearchStatusWrapper, message, STATUS_MIN_COLS, STATUS_MAX_COLS);
    }

    /**
     * Updates the Control status area on the EDT.
     *
     * @param message status text to display (nullable)
     */
    @Override public void onControlStatus(String message) {
        String formattedMessage = formatControlStatusMessage(message);
        Runnable r = () -> {
            StatusViews.setStatus(
                    controlStatus, controlStatusWrapper, formattedMessage, STATUS_MIN_COLS, STATUS_MAX_COLS);
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
            exporterCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_EXPORTER));

            List<String> settingsSub = state.settingsSub() != null ? state.settingsSub() : List.of();
            settingsProjectCheckbox.setSelected(settingsSub.contains(ConfigKeys.SRC_SETTINGS_PROJECT));
            settingsUserCheckbox.setSelected(settingsSub.contains(ConfigKeys.SRC_SETTINGS_USER));

            List<String> trafficTools = state.trafficToolTypes() != null ? state.trafficToolTypes() : List.of();
            trafficBurpAiCheckbox.setSelected(trafficTools.contains("burp_ai"));
            trafficExtensionsCheckbox.setSelected(trafficTools.contains("extensions"));
            trafficIntruderCheckbox.setSelected(trafficTools.contains("intruder"));
            trafficProxyCheckbox.setSelected(trafficTools.contains("proxy"));
            trafficProxyHistoryCheckbox.setSelected(trafficTools.contains("proxy_history"));
            trafficRepeaterCheckbox.setSelected(trafficTools.contains("repeater"));
            trafficScannerCheckbox.setSelected(trafficTools.contains("scanner"));
            trafficSequencerCheckbox.setSelected(trafficTools.contains("sequencer"));

            List<String> severities = state.findingsSeverities() != null ? state.findingsSeverities() : List.of();
            issuesCriticalCheckbox.setSelected(severities.contains("critical"));
            issuesHighCheckbox.setSelected(severities.contains("high"));
            issuesMediumCheckbox.setSelected(severities.contains("medium"));
            issuesLowCheckbox.setSelected(severities.contains("low"));
            issuesInformationalCheckbox.setSelected(severities.contains("informational"));

            List<String> exporterOptions = state.exporterSubOptions() != null ? state.exporterSubOptions() : List.of();
            exporterTraceCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_TRACE));
            exporterDebugCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_DEBUG));
            exporterInfoCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_INFO));
            exporterWarnCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_WARN));
            exporterErrorCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_ERROR));
            exporterStatsCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_STATS));
            exporterConfigCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_CONFIG));
            exporterStatsIntervalField.setText(String.valueOf(state.exporterStatsIntervalSeconds()));
            refreshExporterStatsIntervalEnabledState();
            indexNameBaseTemplateField.setText(state.indexNameBaseTemplate());
            refreshIndexNameBaseValidationState();

            ConfigState.Sinks sinks = state.sinks();
            if (sinks != null) {
                fileSinkCheckbox.setSelected(sinks.filesEnabled());
                filePathField.setText(sinks.filesPath() != null ? sinks.filesPath() : "");
                applyFileFormatSelection(sinks.fileJsonlEnabled(), sinks.fileBulkNdjsonEnabled());
                fileTotalCapCheckbox.setSelected(sinks.fileTotalCapEnabled());
                fileTotalCapField.setText(formatGiBLimit(sinks.fileTotalCapGb()));
                fileDiskUsagePercentCheckbox.setSelected(sinks.fileDiskUsagePercentEnabled());
                fileDiskUsagePercentField.setText(String.valueOf(sinks.fileDiskUsagePercent()));
                openSearchSinkCheckbox.setSelected(sinks.osEnabled());
                openSearchUrlField.setText(sinks.openSearchUrl() != null ? sinks.openSearchUrl() : "");
                openSearchTlsModeCombo.setSelectedItem(labelForTlsMode(sinks.openSearchTlsMode()));
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
            applyEditionRestrictions();
            syncSelectedAuthStateFromUi(state.uiPreferences());
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
        ExporterIndexStatsReporter.refreshScheduleForCurrentState();
    }

    private void syncSelectedAuthStateFromUi() {
        persistSelectedAuthSecrets();
        updateRuntimeConfig();
    }

    private void syncSelectedAuthStateFromUi(ConfigState.UiPreferences uiPreferences) {
        persistSelectedAuthSecrets();
        RuntimeConfig.updateState(buildCurrentState(uiPreferences));
    }

    /** Grey-out and disable each Fields section when no related source option is selected; re-enable when at least one is selected. Does not change checkbox selected state. */
    private void refreshFieldsSectionsEnabled() {
        if (fieldsSectionHeaderRows == null || fieldsExpandButtons == null || fieldsSubPanels == null || fieldCheckboxesByIndex == null) return;
        for (String indexName : ai.attackframework.tools.burp.utils.config.ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            boolean enabled = isAnySourceOptionSelectedForFieldsIndex(indexName);
            boolean disableExpandForCommunity = "findings".equals(indexName) && isCommunityEdition();
            JPanel headerRow = fieldsSectionHeaderRows.get(indexName);
            if (headerRow != null) {
                headerRow.setEnabled(enabled);
                for (java.awt.Component c : headerRow.getComponents()) c.setEnabled(enabled);
            }
            JButton expandBtn = fieldsExpandButtons.get(indexName);
            if (expandBtn != null) expandBtn.setEnabled(!disableExpandForCommunity);
            JPanel sub = fieldsSubPanels.get(indexName);
            if (sub != null) setEnabledRecursively(sub, enabled);
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
            case "tool" -> exporterCheckbox.isSelected() || exporterTraceCheckbox.isSelected() || exporterDebugCheckbox.isSelected()
                    || exporterInfoCheckbox.isSelected() || exporterWarnCheckbox.isSelected() || exporterErrorCheckbox.isSelected()
                    || exporterStatsCheckbox.isSelected() || exporterConfigCheckbox.isSelected();
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
        exporterCheckbox.addActionListener(runtimeUpdater);
        // Defer so checkbox model and other listeners run first, avoiding flakiness when toggling source
        ActionListener refreshFieldsSections = e -> SwingUtilities.invokeLater(this::refreshFieldsSectionsEnabled);
        settingsCheckbox.addActionListener(refreshFieldsSections);
        sitemapCheckbox.addActionListener(refreshFieldsSections);
        issuesCheckbox.addActionListener(refreshFieldsSections);
        trafficCheckbox.addActionListener(refreshFieldsSections);
        exporterCheckbox.addActionListener(refreshFieldsSections);
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
        exporterTraceCheckbox.addActionListener(runtimeUpdater);
        exporterTraceCheckbox.addActionListener(refreshFieldsSections);
        exporterDebugCheckbox.addActionListener(runtimeUpdater);
        exporterDebugCheckbox.addActionListener(refreshFieldsSections);
        exporterInfoCheckbox.addActionListener(runtimeUpdater);
        exporterInfoCheckbox.addActionListener(refreshFieldsSections);
        exporterWarnCheckbox.addActionListener(runtimeUpdater);
        exporterWarnCheckbox.addActionListener(refreshFieldsSections);
        exporterErrorCheckbox.addActionListener(runtimeUpdater);
        exporterErrorCheckbox.addActionListener(refreshFieldsSections);
        exporterStatsCheckbox.addActionListener(e -> {
            refreshExporterStatsIntervalEnabledState();
            updateRuntimeConfig();
        });
        exporterStatsCheckbox.addActionListener(refreshFieldsSections);
        exporterConfigCheckbox.addActionListener(runtimeUpdater);
        exporterConfigCheckbox.addActionListener(refreshFieldsSections);

        allRadio.addActionListener(runtimeUpdater);
        burpSuiteRadio.addActionListener(runtimeUpdater);
        customRadio.addActionListener(runtimeUpdater);

        fileSinkCheckbox.addActionListener(sinkUpdater);
        fileJsonlCheckbox.addActionListener(sinkUpdater);
        fileBulkNdjsonCheckbox.addActionListener(sinkUpdater);
        fileTotalCapCheckbox.addActionListener(sinkUpdater);
        fileDiskUsagePercentCheckbox.addActionListener(sinkUpdater);
        openSearchSinkCheckbox.addActionListener(sinkUpdater);
        openSearchTlsModeCombo.addActionListener(sinkUpdater);

        testConnectionButton.addActionListener(e -> {
            syncSelectedAuthStateFromUi();
            String url = openSearchUrlField.getText().trim();
            if (url.isEmpty()) { onOpenSearchStatus("✖ URL required"); return; }
            onOpenSearchStatus("Testing ...");
            controller().testConnectionAsync(url);
        });
        importPinnedCertificateButton.addActionListener(e -> importPinnedCertificate());
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
            exporterStatsIntervalField.revalidate();
            indexNameBaseTemplateField.revalidate();
            updateRuntimeConfig();
        });
        filePathField.getDocument().addDocumentListener(relayout);
        openSearchUrlField.getDocument().addDocumentListener(relayout);
        fileTotalCapField.getDocument().addDocumentListener(relayout);
        fileDiskUsagePercentField.getDocument().addDocumentListener(relayout);
        exporterStatsIntervalField.getDocument().addDocumentListener(relayout);
        indexNameBaseTemplateField.getDocument().addDocumentListener(relayout);

        DocumentListener authUpdater = Doc.onChange(() -> {
            if (!suppressAuthSync) {
                syncSelectedAuthStateFromUi();
            }
        });
        openSearchUserField.getDocument().addDocumentListener(authUpdater);
        openSearchPasswordField.getDocument().addDocumentListener(authUpdater);
        openSearchApiKeyIdField.getDocument().addDocumentListener(authUpdater);
        openSearchApiKeySecretField.getDocument().addDocumentListener(authUpdater);
        openSearchJwtTokenField.getDocument().addDocumentListener(authUpdater);
        openSearchCertPathField.getDocument().addDocumentListener(authUpdater);
        openSearchCertKeyPathField.getDocument().addDocumentListener(authUpdater);
        openSearchCertPassphraseField.getDocument().addDocumentListener(authUpdater);
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

    private JPanel buildExporterSubPanel() {
        JPanel p = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        p.add(exporterTraceCheckbox);
        p.add(exporterDebugCheckbox);
        p.add(exporterInfoCheckbox);
        p.add(exporterWarnCheckbox);
        p.add(exporterErrorCheckbox);
        p.add(buildExporterStatsRow());
        p.add(exporterConfigCheckbox);
        refreshExporterStatsIntervalEnabledState();
        return p;
    }

    private JPanel buildExporterStatsRow() {
        JPanel row = new JPanel(new MigLayout("insets 0, gapx 8, gapy 0, novisualpadding", "[left][pref][40!][left]", "[]"));
        row.setOpaque(false);
        row.add(exporterStatsCheckbox);
        row.add(Tooltips.label("Interval:",
                Tooltips.html(
                        "Frequency for exporter stats snapshots.",
                        "This controls how often the Exporter index receives stats documents."
                )));
        row.add(exporterStatsIntervalField, "w 40!");
        row.add(new JLabel("sec"));
        return row;
    }

    private void refreshExporterStatsIntervalEnabledState() {
        exporterStatsIntervalField.setEnabled(exporterStatsCheckbox.isSelected());
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
            applyAuthTypeCardVisibility.accept(selectedType);
            if (!suppressAuthSync) {
                syncSelectedAuthStateFromUi();
            }
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

    /** Builds inline TLS controls (mode selection + optional pinned-certificate import). */
    private JPanel buildTlsPanel() {
        openSearchTlsModeCombo.setName("os.tlsMode");
        openSearchTlsModeCombo.setSelectedItem("Verify");
        importPinnedCertificateButton.setName("os.tls.import");

        JPanel pinnedPanel = new JPanel(new MigLayout("insets 0", "[pref]", "[]"));
        pinnedPanel.setOpaque(false);
        pinnedPanel.add(importPinnedCertificateButton);

        JPanel controls = new JPanel(new MigLayout("insets 0, hidemode 3", "[pref]", "[]"));
        controls.setOpaque(false);
        controls.add(Box.createHorizontalStrut(0), "hidemode 3");
        controls.add(pinnedPanel, "hidemode 3");

        java.util.function.Consumer<String> applyPinnedVisibility = selectedMode -> {
            boolean pinned = ConfigState.OPEN_SEARCH_TLS_PINNED.equals(normalizeTlsModeLabel(selectedMode));
            pinnedPanel.setVisible(pinned);
            importPinnedCertificateButton.setVisible(pinned);
            importPinnedCertificateButton.setEnabled(openSearchSinkCheckbox.isSelected() && pinned);
        };
        applyPinnedVisibility.accept(String.valueOf(openSearchTlsModeCombo.getSelectedItem()));
        openSearchTlsModeCombo.addActionListener(e -> {
            String selectedMode = String.valueOf(openSearchTlsModeCombo.getSelectedItem());
            String normalizedMode = normalizeTlsModeLabel(selectedMode);
            applyPinnedVisibility.accept(selectedMode);
            logTlsModeChangeIfNeeded(normalizedMode);
            controls.revalidate();
            controls.repaint();
        });

        String tlsModeTip = Tooltips.html(
                "Select how OpenSearch TLS server certificates are trusted.",
                "- Verify: uses the system trust store.",
                "- Trust pinned certificate: requires an imported X.509 server certificate.",
                "- Trust all certificates: disables verification. Use with caution."
        );
        String importTip = Tooltips.html(
                "Import a pinned X.509 server certificate for OpenSearch TLS trust.",
                "  Common file types: .cer, .crt, .der, .pem.",
                "  The imported certificate bytes and source path are stored only within in-process memory."
        );
        Tooltips.apply(openSearchTlsModeCombo, tlsModeTip);
        Tooltips.apply(importPinnedCertificateButton, importTip);

        JPanel form = new JPanel(new MigLayout("insets 0", "[pref][pref][pref]", "[]"));
        form.setOpaque(false);
        form.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.add(Tooltips.label("TLS mode:", tlsModeTip));
        form.add(openSearchTlsModeCombo);
        form.add(controls, "gapleft 12");
        return form;
    }

    private void importPinnedCertificate() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import OpenSearch TLS Certificate");
        chooser.setAcceptAllFileFilterUsed(true);
        chooser.setFileFilter(new FileNameExtensionFilter(
                "Certificate files (*.cer, *.crt, *.der, *.pem)", "cer", "crt", "der", "pem"));
        int choice = chooser.showOpenDialog(this);
        if (choice != JFileChooser.APPROVE_OPTION) {
            Logger.logDebug("[ConfigPanel] OpenSearch pinned TLS certificate import canceled.");
            return;
        }
        applyPinnedCertificateImport(chooser.getSelectedFile().toPath());
    }

    private void applyPinnedCertificateImport(Path selectedPath) {
        Logger.logDebug("[ConfigPanel] Importing OpenSearch pinned TLS certificate from " + selectedPath);
        try {
            SecureCredentialStore.PinnedTlsCertificate certificate =
                    OpenSearchTlsSupport.importPinnedCertificate(selectedPath);
            SecureCredentialStore.savePinnedTlsCertificate(
                    certificate.sourcePath(), certificate.fingerprintSha256(), certificate.encodedBytes());
            Logger.logInfoPanelOnly("[ConfigPanel] Imported OpenSearch pinned TLS certificate: fingerprint="
                    + certificate.fingerprintSha256() + ", source=" + certificate.sourcePath());
            Logger.logTrace("[ConfigPanel] OpenSearch pinned TLS certificate bytes=" + certificate.encodedBytes().length);
            onOpenSearchStatus("Pinned TLS certificate imported\nTrust: " + certificate.fingerprintSha256()
                    + "\nSource: " + certificate.sourcePath());
        } catch (IOException | java.security.cert.CertificateException e) {
            Logger.logErrorPanelOnly("[ConfigPanel] OpenSearch pinned TLS certificate import failed for "
                    + selectedPath + ": " + rootMessage(e));
            onOpenSearchStatus("Pinned TLS certificate import failed\nDetails: " + rootMessage(e));
        }
    }

    private void logTlsModeChangeIfNeeded(String normalizedMode) {
        if (normalizedMode == null || normalizedMode.equals(lastLoggedTlsMode)) {
            return;
        }
        lastLoggedTlsMode = normalizedMode;
        String label = labelForTlsMode(normalizedMode);
        Logger.logDebug("[ConfigPanel] OpenSearch TLS mode set to " + label + ".");
        if (ConfigState.OPEN_SEARCH_TLS_PINNED.equals(normalizedMode) && !OpenSearchTlsSupport.hasPinnedCertificate()) {
            Logger.logInfoPanelOnly("[ConfigPanel] OpenSearch TLS mode requires an imported pinned certificate before test/start.");
        } else if (ConfigState.OPEN_SEARCH_TLS_INSECURE.equals(normalizedMode)) {
            Logger.logInfoPanelOnly("[ConfigPanel] OpenSearch TLS mode is trusting all certificates insecurely.");
        }
    }

    private static String normalizeTlsModeLabel(String label) {
        if (label == null || label.isBlank()) {
            return ConfigState.OPEN_SEARCH_TLS_VERIFY;
        }
        return switch (label.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "trust pinned certificate" -> ConfigState.OPEN_SEARCH_TLS_PINNED;
            case "trust all certificates" -> ConfigState.OPEN_SEARCH_TLS_INSECURE;
            default -> ConfigState.OPEN_SEARCH_TLS_VERIFY;
        };
    }

    private static String labelForTlsMode(String mode) {
        return switch (ConfigState.normalizeOpenSearchTlsMode(mode)) {
            case ConfigState.OPEN_SEARCH_TLS_PINNED -> "Trust pinned certificate";
            case ConfigState.OPEN_SEARCH_TLS_INSECURE -> "Trust all certificates";
            default -> "Verify";
        };
    }

    private String selectedTlsMode() {
        return normalizeTlsModeLabel(String.valueOf(openSearchTlsModeCombo.getSelectedItem()));
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
        p.add(buildTrafficToolRow(trafficBurpAiCheckbox, trafficBurpAiCommunityIndicator));
        p.add(trafficExtensionsCheckbox);
        p.add(trafficIntruderCheckbox);
        p.add(trafficProxyCheckbox);
        p.add(trafficProxyHistoryCheckbox);
        p.add(trafficRepeaterCheckbox);
        p.add(buildTrafficToolRow(trafficScannerCheckbox, trafficScannerCommunityIndicator));
        p.add(trafficSequencerCheckbox);
        return p;
    }

    private static JPanel buildTrafficToolRow(JCheckBox checkbox, JPanel communityIndicator) {
        JPanel row = new JPanel(new MigLayout("insets 0, aligny center, hidemode 3", "[left]8[pref!]"));
        row.setOpaque(false);
        row.add(checkbox, "aligny center");
        row.add(communityIndicator, "aligny center, hidemode 3");
        return row;
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
            int enabledChildren = 0;
            for (JCheckBox c : safeChildren) {
                if (!c.isEnabled()) {
                    continue;
                }
                enabledChildren++;
                if (c.isSelected()) {
                    selected++;
                }
            }
            if (enabledChildren == 0 || selected == 0) {
                parent.setState(TriStateCheckBox.State.DESELECTED);
            } else if (selected == enabledChildren) {
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
                    if (!child.isEnabled()) {
                        continue;
                    }
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
        refreshExporterStatsIntervalEnabledState();

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
        testConnectionButton.setEnabled(os);
        if (openSearchAuthFormPanel != null) {
            setEnabledRecursively(openSearchAuthFormPanel, os);
        }
        if (openSearchTlsPanel != null) {
            setEnabledRecursively(openSearchTlsPanel, os);
        }
        importPinnedCertificateButton.setEnabled(os
                && ConfigState.OPEN_SEARCH_TLS_PINNED.equals(selectedTlsMode()));
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
     * @return ordered list of source keys suitable for {@link ConfigKeys}
     */
    private List<String> getSelectedSources() {
        List<String> selected = new ArrayList<>();
        if (settingsCheckbox.isSelected()) selected.add(ConfigKeys.SRC_SETTINGS);
        if (sitemapCheckbox.isSelected())  selected.add(ConfigKeys.SRC_SITEMAP);
        if (issuesCheckbox.isSelected())   selected.add(ConfigKeys.SRC_FINDINGS);
        if (trafficCheckbox.isSelected())  selected.add(ConfigKeys.SRC_TRAFFIC);
        if (exporterCheckbox.isSelected()) selected.add(ConfigKeys.SRC_EXPORTER);
        return selected;
    }

    /**
     * Installs undo/redo bindings and enter-key shortcuts on text fields and the TLS mode combo.
     *
     * <p>EDT only. Enter triggers the most relevant action for each field; on the OpenSearch TLS
     * mode dropdown it runs Test Connection when that button is enabled.</p>
     */
    private void wireTextFieldEnhancements() {
        TextFieldUndo.install(filePathField);
        TextFieldUndo.install(openSearchUrlField);
        TextFieldUndo.install(fileTotalCapField);
        TextFieldUndo.install(fileDiskUsagePercentField);
        TextFieldUndo.install(exporterStatsIntervalField);
        TextFieldUndo.install(indexNameBaseTemplateField);
        indexNameBaseTemplateField.getDocument().addDocumentListener(Doc.onChange(this::refreshIndexNameBaseValidationState));
        openSearchUrlField.addActionListener(e -> testConnectionButton.doClick());

        openSearchTlsModeCombo.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), TLS_MODE_ENTER_TEST_CONNECTION);
        openSearchTlsModeCombo.getActionMap().put(TLS_MODE_ENTER_TEST_CONNECTION, new AbstractAction() {
            @Serial private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent e) {
                if (testConnectionButton.isEnabled()) {
                    testConnectionButton.doClick();
                }
            }
        });
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

    private JPanel buildGlobalIndexNamingPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, hidemode 3, gapx 8", "[pref!][pref][pref!]", "[]"));
        panel.setOpaque(false);

        String tooltip = indexBaseNameTooltip();
        panel.add(Tooltips.label("Index Base Name:", tooltip));
        panel.add(indexNameBaseTemplateField, "aligny center");
        panel.add(indexNameBaseValidationIndicator, "aligny center");
        return panel;
    }

    /** Prepares the inline Index Base Name validation indicator to match regex-style glyph feedback. */
    private void configureIndexNameBaseValidationUi() {
        ValidationIndicator.hide(indexNameBaseValidationIndicator, indexNameBaseTemplateField.getFont());
    }

    /** Revalidates the Index Base Name field against the same OpenSearch rules used at Start. */
    private void refreshIndexNameBaseValidationState() {
        ai.attackframework.tools.burp.utils.IndexNaming.BaseTemplateValidation validation =
                ai.attackframework.tools.burp.utils.IndexNaming.validateBaseTemplateDetailed(
                indexNameBaseTemplateField.getText(),
                Instant.now());
        if (validation.valid()) {
            ValidationIndicator.good(
                    indexNameBaseValidationIndicator,
                    indexNameBaseTemplateField.getFont(),
                    validIndexBaseNameTooltip());
        } else {
            ValidationIndicator.bad(
                    indexNameBaseValidationIndicator,
                    indexNameBaseTemplateField.getFont(),
                    invalidIndexBaseNameTooltip(validation));
        }
        if (indexNameBaseValidationIndicator.getParent() != null) {
            indexNameBaseValidationIndicator.getParent().revalidate();
            indexNameBaseValidationIndicator.getParent().repaint();
        }
    }

    private static String indexBaseNameTooltip() {
        return Tooltips.htmlRaw(
                "<b>Index Base Name</b>",
                "Shared base used to derive all OpenSearch index names and file basenames.",
                "Enter only the shared base. Fixed suffixes are appended automatically:",
                "&nbsp;&nbsp;<code>-exporter</code>, <code>-findings</code>, <code>-settings</code>, <code>-sitemap</code>, <code>-traffic</code>",
                "",
                "Default:",
                "&nbsp;&nbsp;<code>attackframework-tool-burp</code>",
                "",
                "Examples:",
                "&nbsp;&nbsp;<code>attackframework-tool-burp</code>",
                "&nbsp;&nbsp;<code>${now:yyyyMMdd}-attackframework-tool-burp</code>",
                "&nbsp;&nbsp;<code>${now:yyyyMMdd-HHmmss}-attackframework-tool-burp</code>",
                "",
                "Supported date-time variables:",
                "&nbsp;&nbsp;<code>{NOW}</code> or <code>{DATE-TIME}</code> for the built-in current local date/time value",
                "&nbsp;&nbsp;<code>${now:yyyyMMdd}</code> or <code>${now:yyyyMMdd-HHmmss}</code> for explicit Java date-time formats",
                "",
                "OpenSearch requirements after suffixes are appended:",
                "&nbsp;&nbsp;- lowercase only",
                "&nbsp;&nbsp;- cannot start with <code>-</code>, <code>_</code>, or <code>+</code>",
                "&nbsp;&nbsp;- cannot be <code>.</code> or <code>..</code>",
                "&nbsp;&nbsp;- cannot contain spaces or <code>\\ / * ? \" &lt; &gt; | , # :</code>",
                "&nbsp;&nbsp;- cannot contain unresolved variable syntax",
                "&nbsp;&nbsp;- must stay within 255 UTF-8 bytes",
                "",
                "Resolution timing:",
                "&nbsp;&nbsp;Date-time variables resolve on each <b>Start</b> and remain fixed for that full run."
        );
    }

    private static String validIndexBaseNameTooltip() {
        return Tooltips.htmlRaw(
                "<b>Valid Index Base Name</b>",
                "All resolved index names currently satisfy the OpenSearch naming rules.",
                "Blank is also allowed and falls back to <code>attackframework-tool-burp</code>."
        );
    }

    private static String invalidIndexBaseNameTooltip(
            ai.attackframework.tools.burp.utils.IndexNaming.BaseTemplateValidation validation) {
        String displayName = Tooltips.escapeHtml(validation.failingDisplayName());
        String resolvedName = Tooltips.escapeHtml(validation.failingResolvedName());
        String error = Tooltips.escapeHtml(validation.error());
        return Tooltips.htmlRaw(
                "<b>Invalid Index Base Name</b>",
                "<b>Error:</b> " + error,
                "<b>Failing resolved index:</b> " + displayName,
                "<b>Resolved name:</b> <code>" + resolvedName + "</code>",
                "",
                "<b>Requirements</b>",
                "All resolved index names must:",
                "&nbsp;&nbsp;- be lowercase",
                "&nbsp;&nbsp;- not start with <code>-</code>, <code>_</code>, or <code>+</code>",
                "&nbsp;&nbsp;- not be <code>.</code> or <code>..</code>",
                "&nbsp;&nbsp;- not contain spaces or <code>\\ / * ? \" &lt; &gt; | , # :</code>",
                "&nbsp;&nbsp;- not contain unsupported or unresolved variable syntax",
                "&nbsp;&nbsp;- stay within 255 UTF-8 bytes after the suffix is appended"
        );
    }

    /** Returns {@code value} if non-null and non-blank, otherwise {@code fallback}. */
    private static String nonBlankOr(String value, String fallback) {
        return (value != null && !value.isBlank()) ? value.trim() : (fallback != null ? fallback : "");
    }

    /**
     * Builds the current UI state into a serializable config object.
     *
     * @return assembled {@link ConfigState.State} reflecting user selections
     */
    private ConfigState.State buildCurrentState() {
        return buildCurrentState(currentUiPreferences());
    }

    private ConfigState.State buildCurrentState(ConfigState.UiPreferences uiPreferences) {
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
        if (trafficBurpAiCheckbox.isSelected()) trafficToolTypes.add("burp_ai");
        if (trafficExtensionsCheckbox.isSelected()) trafficToolTypes.add("extensions");
        if (trafficIntruderCheckbox.isSelected()) trafficToolTypes.add("intruder");
        if (trafficProxyCheckbox.isSelected()) trafficToolTypes.add("proxy");
        if (trafficProxyHistoryCheckbox.isSelected()) trafficToolTypes.add("proxy_history");
        if (trafficRepeaterCheckbox.isSelected()) trafficToolTypes.add("repeater");
        if (trafficScannerCheckbox.isSelected()) trafficToolTypes.add("scanner");
        if (trafficSequencerCheckbox.isSelected()) trafficToolTypes.add("sequencer");

        List<String> findingsSeverities = new ArrayList<>();
        if (issuesCriticalCheckbox.isSelected()) findingsSeverities.add("critical");
        if (issuesHighCheckbox.isSelected()) findingsSeverities.add("high");
        if (issuesMediumCheckbox.isSelected()) findingsSeverities.add("medium");
        if (issuesLowCheckbox.isSelected()) findingsSeverities.add("low");
        if (issuesInformationalCheckbox.isSelected()) findingsSeverities.add("informational");

        List<String> exporterSubOptions = new ArrayList<>();
        if (exporterTraceCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_TRACE);
        if (exporterDebugCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_DEBUG);
        if (exporterInfoCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_INFO);
        if (exporterWarnCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_WARN);
        if (exporterErrorCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_ERROR);
        if (exporterStatsCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_STATS);
        if (exporterConfigCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_CONFIG);

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
                                ConfigState.DEFAULT_FILE_TOTAL_CAP_GB),
                        fileDiskUsagePercentCheckbox.isSelected(), parsePercentLimit(fileDiskUsagePercentField.getText(),
                                ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT),
                        osEnabled, osUrl,
                        osUser,
                        osPass,
                        selectedTlsMode()),
                settingsSub,
                trafficToolTypes,
                findingsSeverities,
                exporterSubOptions,
                parsePositiveSeconds(exporterStatsIntervalField.getText(),
                        ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS),
                nonBlankOr(indexNameBaseTemplateField.getText(), ConfigState.DEFAULT_INDEX_NAME_BASE_TEMPLATE),
                buildEnabledExportFieldsByIndex(),
                uiPreferences
        );
    }

    private static ConfigState.UiPreferences currentUiPreferences() {
        ConfigState.State current = RuntimeConfig.getState();
        return current == null || current.uiPreferences() == null
                ? ConfigState.defaultUiPreferences()
                : current.uiPreferences();
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
     * <p>Invalid, blank, or non-positive input falls back to {@code defaultGb}. Values are rounded
     * to three decimals so import/export remains stable for user-entered values such as
     * {@code 1.25}.</p>
     */
    private static double parseGiBLimit(String raw, double defaultGb) {
        try {
            BigDecimal gib = new BigDecimal(nonBlankOr(raw, "").trim());
            if (gib.compareTo(BigDecimal.ZERO) <= 0) {
                return defaultGb;
            }
            return gib.setScale(3, RoundingMode.HALF_UP).stripTrailingZeros().doubleValue();
        } catch (RuntimeException e) {
            return defaultGb;
        }
    }

    /** Formats a GB limit back to a trimmed string suitable for the UI text fields. */
    private static String formatGiBLimit(double gb) {
        if (gb <= 0) {
            return "1";
        }
        return BigDecimal.valueOf(gb)
                .setScale(3, RoundingMode.HALF_UP)
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

    private static int parsePositiveSeconds(String raw, int defaultSeconds) {
        try {
            int seconds = Integer.parseInt(nonBlankOr(raw, ""));
            return seconds > 0 ? seconds : defaultSeconds;
        } catch (NumberFormatException e) {
            return defaultSeconds;
        }
    }

    /**
     * Prompts for a save location and exports the current config to JSON asynchronously.
     *
     * <p>EDT only. Uses {@link FileUtil#ensureJsonExtension(java.io.File)} to normalize the file
     * name before delegating to {@link ConfigController#exportConfigAsync(java.nio.file.Path, String)}.</p>
     */
    private void exportConfig() {
        ConfigState.State currentState = buildCurrentState();
        ai.attackframework.tools.burp.utils.IndexNaming.ResolutionResult indexNamingResolution =
                ai.attackframework.tools.burp.utils.IndexNaming.resolveAllConfiguredNames(
                        currentState,
                        java.time.Instant.now());
        if (!indexNamingResolution.valid()) {
            onControlStatus("Fix index naming before export: " + String.join(" ", indexNamingResolution.errors()));
            return;
        }
        String json = ConfigJsonMapper.build(currentState);
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
        exporterCheckbox.setName("src.exporter");
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
        exporterTraceCheckbox.setName("src.exporter.trace");
        exporterDebugCheckbox.setName("src.exporter.debug");
        exporterInfoCheckbox.setName("src.exporter.info");
        exporterWarnCheckbox.setName("src.exporter.warn");
        exporterErrorCheckbox.setName("src.exporter.error");
        exporterStatsCheckbox.setName("src.exporter.stats");
        exporterStatsIntervalField.setName("src.exporter.stats.intervalSeconds");
        exporterConfigCheckbox.setName("src.exporter.config");
        exporterExpandButton.setName("src.exporter.expand");
        indexNameBaseTemplateField.setName("indexNaming.baseTemplate");
        indexNameBaseValidationIndicator.setName("indexNaming.baseTemplate.indicator");

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
        Tooltips.apply(exporterCheckbox, Tooltips.html(
                "Burp Exporter runtime logs and metrics.",
                "Controls logs, stats snapshots, and config snapshots exported to the Exporter index."
        ));
        Tooltips.apply(settingsExpandButton, Tooltips.html("Settings sub-options."));
        Tooltips.apply(issuesExpandButton, Tooltips.html("Issues sub-options."));
        Tooltips.apply(trafficExpandButton, Tooltips.html("Traffic sub-options."));
        Tooltips.apply(exporterExpandButton, Tooltips.html("Exporter sub-options."));
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
        Tooltips.apply(exporterTraceCheckbox, Tooltips.html("Exporter trace-level log events."));
        Tooltips.apply(exporterDebugCheckbox, Tooltips.html("Exporter debug-level log events."));
        Tooltips.apply(exporterInfoCheckbox, Tooltips.html("Exporter info-level log events."));
        Tooltips.apply(exporterWarnCheckbox, Tooltips.html("Exporter warning log events."));
        Tooltips.apply(exporterErrorCheckbox, Tooltips.html("Exporter error log events."));
        Tooltips.apply(exporterStatsCheckbox, Tooltips.html(
                "Periodic exporter runtime stats snapshots.",
                "These documents include resource usage and exporter counters."
        ));
        Tooltips.apply(exporterStatsIntervalField, Tooltips.html(
                "Stats snapshot interval in seconds.",
                "Default: 30 seconds."
        ));
        Tooltips.apply(exporterConfigCheckbox, Tooltips.html(
                "Exporter config snapshots when Start completes.",
                "Includes the normalized source, scope, and destination selections."
        ));
        Tooltips.apply(indexNameBaseTemplateField, indexBaseNameTooltip());

        Tooltips.apply(allRadio, Tooltips.html("Export all observed."));
        Tooltips.apply(burpSuiteRadio, Tooltips.html("Export Burp Suite's project scope."));
        Tooltips.apply(customRadio, Tooltips.html("Export custom scope."));

        Tooltips.apply(fileSinkCheckbox, Tooltips.html("Enable file-based export."));
        Tooltips.apply(filePathField, Tooltips.htmlRaw(
                "Root directory for generated files. Examples:",
                "&nbsp;&nbsp;/path/to/directory",
                "&nbsp;&nbsp;c:\\path\\to\\directory"
        ));
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
        Tooltips.apply(openSearchUrlField, Tooltips.htmlRaw("Base URL of the OpenSearch cluster. Examples:",
                "&nbsp;&nbsp;https://opensearch.url:9200",
                "&nbsp;&nbsp;http://10.0.0.1:9200"));
        Tooltips.apply(testConnectionButton, Tooltips.html(
                "Test connectivity and authentication against OpenSearch.",
                "Status output includes connection, authentication, trust, and reported version.",
                "Secrets are only stored within in-process memory."
        ));
    }

    /**
     * Runs a task on the EDT, executing immediately when already on the EDT.
     *
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

    private static String rootMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        String message = current.getMessage();
        return (message == null || message.isBlank()) ? current.getClass().getSimpleName() : message;
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
