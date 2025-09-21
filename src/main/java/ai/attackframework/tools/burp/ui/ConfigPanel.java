package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigState;
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
import java.io.ObjectInputStream;
import java.io.Serial;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * UI panel for configuring data sources, scope, sinks, and admin actions.
 *
 * <p>All Swing updates are expected on the EDT.</p>
 */
public class ConfigPanel extends JPanel implements ConfigController.Ui {

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

    // Sources
    private final JCheckBox settingsCheckbox = new JCheckBox("Settings", true);
    private final JCheckBox sitemapCheckbox  = new JCheckBox("Sitemap",  true);
    private final JCheckBox issuesCheckbox   = new JCheckBox("Issues",   true);
    private final JCheckBox trafficCheckbox  = new JCheckBox("Traffic",  true);

    // Scope radios
    private final JRadioButton allRadio       = new JRadioButton("All");
    private final JRadioButton burpSuiteRadio = new JRadioButton("Burp Suite's", true);

    // Scope grid (custom)
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

    /**
     * Controller for long-running actions.
     *
     * <p>Marked {@code transient} because {@link javax.swing.JPanel} is {@link java.io.Serializable}
     * but this collaborator is not. The controller is reconstructed by a private
     * {@code readObject(ObjectInputStream)} after deserialization.</p>
     */
    private transient ConfigController controller = new ConfigController(this);

    public ConfigPanel() {
        setLayout(new MigLayout("fillx, insets 12", "[fill]"));

        add(new ConfigSourcesPanel(settingsCheckbox, sitemapCheckbox, issuesCheckbox, trafficCheckbox, INDENT).build(),
                "gaptop 5, gapbottom 5, wrap");
        add(panelSeparator(), MIG_GROWX_WRAP);

        add(buildScopePanel(), "gaptop 10, gapbottom 5, wrap");
        add(panelSeparator(), MIG_GROWX_WRAP);

        // Locals: import/export status area (used only to build the admin panel)
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

    // ---- ConfigController.Ui implementation ----

    @Override
    public void onFileStatus(String message) {
        setStatus(fileStatus, fileStatusWrapper, message);
    }

    @Override
    public void onOpenSearchStatus(String message) {
        setStatus(openSearchStatus, statusWrapper, message);
    }

    @Override
    public void onAdminStatus(String message) {
        setStatus(adminStatus, adminStatusWrapper, message);
        // preserve the existing timed hide behavior
        if (adminStatusHideTimer != null && adminStatusHideTimer.isRunning()) adminStatusHideTimer.stop();
        adminStatusHideTimer = new Timer(3000, evt -> {
            adminStatusWrapper.setVisible(false);
            adminStatusWrapper.revalidate();
            adminStatusWrapper.repaint();
        });
        adminStatusHideTimer.setRepeats(false);
        adminStatusHideTimer.start();
    }

    @Override
    public void onImportResult(ConfigState.State state) {
        // Apply typed state to UI (EDT).
        settingsCheckbox.setSelected(state.dataSources().contains("settings"));
        sitemapCheckbox.setSelected(state.dataSources().contains("sitemap"));
        issuesCheckbox.setSelected(state.dataSources().contains("findings"));
        trafficCheckbox.setSelected(state.dataSources().contains("traffic"));

        switch (state.scopeType()) {
            case SCOPE_CUSTOM -> {
                scopeGrid.customRadio().setSelected(true);
                if (!state.customEntries().isEmpty()) {
                    scopeGrid.setFirstValue(state.customEntries().getFirst().value());
                } else {
                    scopeGrid.setFirstValue("");
                }
            }
            case SCOPE_BURP -> burpSuiteRadio.setSelected(true);
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
    }

    // ---- Status helpers ----

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

    private static int maxLineLength(String[] lines) {
        int max = 1;
        for (String s : lines) if (s != null && s.length() > max) max = s.length();
        return max;
    }

    // ---- Wiring (delegates to controller) ----

    private void wireButtonActions() {
        fileSinkCheckbox.addItemListener(e -> refreshEnabledStates());
        openSearchSinkCheckbox.addItemListener(e -> refreshEnabledStates());

        createFilesButton.addActionListener(e -> {
            String root = filePathField.getText().trim();
            if (root.isEmpty()) {
                onFileStatus("✖ Path required");
                return;
            }
            controller.createFilesAsync(root, getSelectedSources());
        });

        testConnectionButton.addActionListener(e -> {
            String url = openSearchUrlField.getText().trim();
            if (url.isEmpty()) {
                onOpenSearchStatus("✖ URL required");
                return;
            }
            controller.testConnectionAsync(url);
        });

        createIndexesButton.addActionListener(e -> {
            String url = openSearchUrlField.getText().trim();
            if (url.isEmpty()) {
                onOpenSearchStatus("✖ URL required");
                return;
            }
            controller.createIndexesAsync(url, getSelectedSources());
        });

        // re-layout textfields when content changes
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
            controller.saveAsync(buildCurrentState());
        }
    }

    /** Compose the current typed state from UI controls (EDT). */
    private ConfigState.State buildCurrentState() {
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
            scopeType = SCOPE_ALL;
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

    // ---- Import / Export dialog handlers (delegating to controller) ----

    private void exportConfig() {
        String json = ConfigJsonMapper.build(buildCurrentState());

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        chooser.setSelectedFile(new File("attackframework-burp-exporter-config.json"));

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            onAdminStatus("Export cancelled.");
            return;
        }
        Path out = ai.attackframework.tools.burp.utils.FileUtil
                .ensureJsonExtension(chooser.getSelectedFile()).toPath();
        controller.exportConfigAsync(out, json);
    }

    private void importConfig() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));

        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            onAdminStatus("Import cancelled.");
            return;
        }
        controller.importConfigAsync(chooser.getSelectedFile().toPath());
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

    /* ------------ Deserialization hook: rebuild transient collaborators ------------ */

    /**
     * Rebuilds the {@link #controller} after default deserialization.
     *
     * @param in the stream to read from
     * @throws IOException if the stream read fails
     * @throws ClassNotFoundException if a required class cannot be found
     */
    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        this.controller = new ConfigController(this);
    }
}
