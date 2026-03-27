package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JToolTip;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import net.miginfocom.swing.MigLayout;

/**
 * Headless tests for {@link ConfigControlPanel}: layout, stable component names,
 * and Start/Stop button and indicator behaviour.
 *
 * <p>Builds the panel in isolation with no-op or recording actions. All UI
 * interaction runs on the EDT.</p>
 */
class ConfigControlPanelHeadlessTest {

    private static final String MIG_STATUS_INSETS = "insets 5, novisualpadding";
    private static final String MIG_PREF_COL = "[pref!]";

    private static void resetExportRunning() {
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void control_panel_has_header_and_named_components() throws Exception {
        resetExportRunning();
        try {
            JPanel root = buildPanel(noOpStartAction(), noOpRunnables(), noOpActionListener());

            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });

            JLabel header = findLabelByText(root, "Config Control");
            assertThat(header).as("Config Control header").isNotNull();
            assertThat(header.getText()).isEqualTo("Config Control");
            assertThat(header.getToolTipText())
                    .isEqualTo("<html>Import, export, save and apply the configuration.<br>Start or stop Burp Exporter.</html>");

            JButton save = findByName(root, "control.save", JButton.class);
            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            assertThat(save).as("control.save").isNotNull();
            assertThat(save.getText()).isEqualTo("Save");
            assertThat(save.getToolTipText())
                    .isEqualTo("<html>Save and apply the current configuration.<br>Secrets are only stored within in-process memory.</html>");
            assertThat(startStop).as("control.startStop").isNotNull();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(startStop.getToolTipText()).isEqualTo("<html>Start exporting to the configured destination(s).</html>");
            assertThat(indicator).as("control.exportIndicator").isNotNull();
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void control_tooltip_owners_create_html_enabled_tooltips() throws Exception {
        resetExportRunning();
        try {
            JPanel root = buildPanel(noOpStartAction(), noOpRunnables(), noOpActionListener());

            JButton save = findByName(root, "control.save", JButton.class);
            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            runEdt(() -> {
                JToolTip saveToolTip = save.createToolTip();
                JToolTip startStopToolTip = startStop.createToolTip();
                JToolTip indicatorToolTip = indicator.createToolTip();

                assertThat(saveToolTip.getComponent()).isSameAs(save);
                assertThat(startStopToolTip.getComponent()).isSameAs(startStop);
                assertThat(indicatorToolTip.getComponent()).isSameAs(indicator);
                assertThat(saveToolTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
                assertThat(startStopToolTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
                assertThat(indicatorToolTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
            });
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void control_panel_buttons_have_expected_labels() throws Exception {
        resetExportRunning();
        try {
            JPanel root = buildPanel(noOpStartAction(), noOpRunnables(), noOpActionListener());
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });

            List<JButton> buttons = collect(root, JButton.class);
            List<String> texts = buttons.stream().map(JButton::getText).toList();
            assertThat(texts).contains("Import Config", "Export Config", "Save", "Start");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void start_stop_click_invokes_actions_and_updates_button_indicator_and_status() throws Exception {
        resetExportRunning();
        try {
            AtomicInteger startCount = new AtomicInteger(0);
            AtomicInteger stopCount = new AtomicInteger(0);
            AtomicReference<JTextArea> controlStatusRef = new AtomicReference<>();
            JPanel root = buildPanel(
                    onStartFailure -> { startCount.incrementAndGet(); RuntimeConfig.setExportRunning(true); },
                    () -> { stopCount.incrementAndGet(); RuntimeConfig.setExportRunning(false); },
                    noOpActionListener(),
                    controlStatusRef
            );

            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });

            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");

            runEdt(() -> startStop.doClick());
            runEdt(() -> { /* flush EDT so deferred start action runs */ });
            assertThat(startCount.get()).isEqualTo(1);
            assertThat(stopCount.get()).isEqualTo(0);
            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(startStop.getText()).isEqualTo("Stop");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is starting</html>");
            assertThat(controlStatusRef.get().getText()).isEqualTo("Starting ...");

            runEdt(() -> startStop.doClick());
            assertThat(startCount.get()).isEqualTo(1);
            assertThat(stopCount.get()).isEqualTo(1);
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");
            assertThat(controlStatusRef.get().getText()).isEqualTo("Stopped");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void start_action_calling_onStartFailure_reverts_button_and_indicator_to_stopped() throws Exception {
        resetExportRunning();
        try {
            JPanel root = buildPanel(
                    callbacks -> callbacks.onStartFailure().run(),
                    noOpRunnables(),
                    noOpActionListener()
            );
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            runEdt(() -> startStop.doClick());
            runEdt(() -> { /* flush EDT so deferred start action runs and calls onStartFailure */ });
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void start_action_calling_onStartSuccess_marks_indicator_running_and_sets_running_status() throws Exception {
        resetExportRunning();
        try {
            AtomicReference<JTextArea> controlStatusRef = new AtomicReference<>();
            JPanel root = buildPanel(
                    callbacks -> callbacks.onStartSuccess().run(),
                    noOpRunnables(),
                    noOpActionListener(),
                    controlStatusRef
            );
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            runEdt(() -> startStop.doClick());
            runEdt(() -> { });

            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(startStop.getText()).isEqualTo("Stop");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is running</html>");
            assertThat(controlStatusRef.get().getText()).isEqualTo("Running");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void stop_clicked_before_deferred_start_runs_keeps_control_stopped() throws Exception {
        resetExportRunning();
        try {
            AtomicInteger startAcceptedCount = new AtomicInteger(0);
            AtomicInteger stopCount = new AtomicInteger(0);
            JPanel root = buildPanel(
                    onStartFailure -> {
                        if (!RuntimeConfig.isExportRunning()) {
                            return;
                        }
                        startAcceptedCount.incrementAndGet();
                    },
                    () -> {
                        stopCount.incrementAndGet();
                        RuntimeConfig.setExportRunning(false);
                    },
                    noOpActionListener()
            );
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            runEdt(() -> {
                startStop.doClick();
                assertThat(RuntimeConfig.isExportRunning()).isTrue();
                assertThat(startStop.getText()).isEqualTo("Stop");
                assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is starting</html>");
                startStop.doClick();
            });
            assertThat(stopCount.get()).isEqualTo(1);
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");

            runEdt(() -> { /* flush deferred start callback */ });
            assertThat(startAcceptedCount.get()).isEqualTo(0);
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void when_export_running_panel_builds_with_stop_label() throws Exception {
        resetExportRunning();
        try {
            RuntimeConfig.setExportRunning(true);
            JPanel root = buildPanel(noOpStartAction(), noOpRunnables(), noOpActionListener());
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });

            JButton startStop = findByName(root, "control.startStop", JButton.class);
            assertThat(startStop.getText()).isEqualTo("Stop");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void control_components_findable_inside_config_panel() throws Exception {
        resetExportRunning();
        try {
            ConfigPanel configPanel = new ConfigPanel();
            runEdt(() -> {
                configPanel.setSize(1000, 700);
                configPanel.doLayout();
            });

            JButton save = findByName(configPanel, "control.save", JButton.class);
            JButton startStop = findByName(configPanel, "control.startStop", JButton.class);
            JComponent indicator = findByName(configPanel, "control.exportIndicator", JComponent.class);
            JLabel header = findLabelByText(configPanel, "Config Control");

            assertThat(header).isNotNull();
            assertThat(save.getText()).isEqualTo("Save");
            assertThat(startStop.getText()).isIn("Start", "Stop");
            assertThat(indicator).isNotNull();
        } finally {
            resetExportRunning();
        }
    }

    // ---- helpers ----

    private static JPanel buildPanel(
            Consumer<ConfigControlPanel.StartUiCallbacks> startAction,
            Runnable stopAction,
            ActionListener saveAction
    ) {
        return buildPanel(startAction, stopAction, saveAction, new AtomicReference<>());
    }

    private static JPanel buildPanel(
            Consumer<ConfigControlPanel.StartUiCallbacks> startAction,
            Runnable stopAction,
            ActionListener saveAction,
            AtomicReference<JTextArea> controlStatusRef
    ) {
        JTextArea importExportStatus = new JTextArea();
        JPanel importExportStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));
        JTextArea controlStatus = new JTextArea();
        controlStatusRef.set(controlStatus);
        JPanel controlStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

        ConfigControlPanel panel = new ConfigControlPanel(
                importExportStatus,
                importExportStatusWrapper,
                controlStatus,
                controlStatusWrapper,
                30,
                15,
                ta -> { },
                () -> { },
                () -> { },
                saveAction,
                startAction,
                stopAction
        );
        return panel.build();
    }

    private static Consumer<ConfigControlPanel.StartUiCallbacks> noOpStartAction() {
        return callbacks -> { };
    }

    private static Runnable noOpRunnables() {
        return () -> { };
    }

    private static ActionListener noOpActionListener() {
        return e -> { };
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        List<T> all = new ArrayList<>();
        collectByType(root, type, all);
        for (T c : all) {
            if (name.equals(c.getName())) return c;
        }
        throw new AssertionError("Component not found: name=" + name + " type=" + type.getSimpleName());
    }

    private static JLabel findLabelByText(Container root, String text) {
        List<JLabel> all = new ArrayList<>();
        collectByType(root, JLabel.class, all);
        for (JLabel lbl : all) {
            if (text.equals(lbl.getText())) return lbl;
        }
        throw new AssertionError("JLabel with text not found: " + text);
    }

    private static <T extends Component> void collectByType(Container root, Class<T> type, List<T> out) {
        if (type.isInstance(root)) out.add(type.cast(root));
        for (Component comp : root.getComponents()) {
            if (comp instanceof Container cont) collectByType(cont, type, out);
            else if (type.isInstance(comp)) out.add(type.cast(comp));
        }
    }

    private static List<JButton> collect(Container root, Class<JButton> type) {
        List<JButton> out = new ArrayList<>();
        collectByType(root, type, out);
        return out;
    }

    private static void runEdt(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeAndWait(r);
    }
}
