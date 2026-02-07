package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.AfterEach;
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

    @AfterEach
    void resetExportRunning() {
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void control_panel_has_header_and_named_components() throws Exception {
        RuntimeConfig.setExportRunning(false);
        JPanel root = buildPanel(noOpRunnables(), noOpRunnables(), noOpActionListener());

        runEdt(() -> {
            root.setSize(600, 400);
            root.doLayout();
        });

        JLabel header = findLabelByText(root, "Control");
        assertThat(header).as("Control header").isNotNull();
        assertThat(header.getText()).isEqualTo("Control");

        JButton save = findByName(root, "control.save", JButton.class);
        JButton startStop = findByName(root, "control.startStop", JButton.class);
        JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

        assertThat(save).as("control.save").isNotNull();
        assertThat(save.getText()).isEqualTo("Save");
        assertThat(startStop).as("control.startStop").isNotNull();
        assertThat(startStop.getText()).isEqualTo("Start");
        assertThat(indicator).as("control.exportIndicator").isNotNull();
    }

    @Test
    void control_panel_buttons_have_expected_labels() throws Exception {
        RuntimeConfig.setExportRunning(false);
        JPanel root = buildPanel(noOpRunnables(), noOpRunnables(), noOpActionListener());
        runEdt(() -> {
            root.setSize(600, 400);
            root.doLayout();
        });

        List<JButton> buttons = collect(root, JButton.class);
        List<String> texts = buttons.stream().map(JButton::getText).toList();
        assertThat(texts).contains("Import Config", "Export Config", "Save", "Start");
    }

    @Test
    void start_stop_click_invokes_actions_and_updates_button_and_indicator() throws Exception {
        RuntimeConfig.setExportRunning(false);
        AtomicInteger startCount = new AtomicInteger(0);
        AtomicInteger stopCount = new AtomicInteger(0);
        JPanel root = buildPanel(
                () -> { startCount.incrementAndGet(); RuntimeConfig.setExportRunning(true); },
                () -> { stopCount.incrementAndGet(); RuntimeConfig.setExportRunning(false); },
                noOpActionListener()
        );

        runEdt(() -> {
            root.setSize(600, 400);
            root.doLayout();
        });

        JButton startStop = findByName(root, "control.startStop", JButton.class);
        JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

        assertThat(startStop.getText()).isEqualTo("Start");
        assertThat(indicator.getToolTipText()).isEqualTo("Export is stopped");

        runEdt(() -> startStop.doClick());
        assertThat(startCount.get()).isEqualTo(1);
        assertThat(stopCount.get()).isEqualTo(0);
        assertThat(RuntimeConfig.isExportRunning()).isTrue();
        assertThat(startStop.getText()).isEqualTo("Stop");
        assertThat(indicator.getToolTipText()).isEqualTo("Export is running");

        runEdt(() -> startStop.doClick());
        assertThat(startCount.get()).isEqualTo(1);
        assertThat(stopCount.get()).isEqualTo(1);
        assertThat(RuntimeConfig.isExportRunning()).isFalse();
        assertThat(startStop.getText()).isEqualTo("Start");
        assertThat(indicator.getToolTipText()).isEqualTo("Export is stopped");
    }

    @Test
    void when_export_running_panel_builds_with_stop_label() throws Exception {
        RuntimeConfig.setExportRunning(true);
        JPanel root = buildPanel(noOpRunnables(), noOpRunnables(), noOpActionListener());
        runEdt(() -> {
            root.setSize(600, 400);
            root.doLayout();
        });

        JButton startStop = findByName(root, "control.startStop", JButton.class);
        assertThat(startStop.getText()).isEqualTo("Stop");
    }

    @Test
    void control_components_findable_inside_config_panel() throws Exception {
        ConfigPanel configPanel = new ConfigPanel();
        runEdt(() -> {
            configPanel.setSize(1000, 700);
            configPanel.doLayout();
        });

        JButton save = findByName(configPanel, "control.save", JButton.class);
        JButton startStop = findByName(configPanel, "control.startStop", JButton.class);
        JComponent indicator = findByName(configPanel, "control.exportIndicator", JComponent.class);
        JLabel header = findLabelByText(configPanel, "Control");

        assertThat(header).isNotNull();
        assertThat(save.getText()).isEqualTo("Save");
        assertThat(startStop.getText()).isIn("Start", "Stop");
        assertThat(indicator).isNotNull();
    }

    // ---- helpers ----

    private static JPanel buildPanel(
            Runnable startAction,
            Runnable stopAction,
            ActionListener saveAction
    ) {
        JTextArea importExportStatus = new JTextArea();
        JPanel importExportStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));
        JTextArea controlStatus = new JTextArea();
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
