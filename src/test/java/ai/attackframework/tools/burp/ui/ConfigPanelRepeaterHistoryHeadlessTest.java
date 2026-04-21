package ai.attackframework.tools.burp.ui;

import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JCheckBox;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.Reflect;
import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.config.ConfigState;

class ConfigPanelRepeaterHistoryHeadlessTest {

    @Test
    void repeaterHistoryTrafficOption_defaultsEnabled_andPersistsIntoBuiltState() throws Exception {
        ConfigPanel panel = createPanel();

        JCheckBox repeaterHistoryCheckbox = Reflect.get(panel, "trafficRepeaterHistoryCheckbox");

        ConfigState.State state = (ConfigState.State) Reflect.call(panel, "buildCurrentState");

        assertThat(repeaterHistoryCheckbox.isSelected()).isTrue();
        assertThat(repeaterHistoryCheckbox.getToolTipText()).contains("Historic traffic from Repeater tabs");
        assertThat(repeaterHistoryCheckbox.getToolTipText()).contains("one-time snapshot when Start is clicked");
        assertThat(repeaterHistoryCheckbox.getToolTipText()).contains("best-effort Repeater tab and group labels");
        assertThat(repeaterHistoryCheckbox.getToolTipText()).contains("For ongoing and future Repeater traffic, select Repeater");
        assertThat(repeaterHistoryCheckbox.getToolTipText()).doesNotContain("may miss");
        assertThat(repeaterHistoryCheckbox.getToolTipText()).doesNotContain("enable or disable each one independently");
        assertThat(state.trafficToolTypes()).contains("repeater_history");
    }

    @Test
    void onImportResult_restoresRepeaterHistoryTrafficOption() throws Exception {
        ConfigPanel panel = createPanel();
        JCheckBox repeaterHistoryCheckbox = Reflect.get(panel, "trafficRepeaterHistoryCheckbox");

        ConfigState.State imported = new ConfigState.State(
                java.util.List.of("traffic"),
                "all",
                java.util.List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                java.util.List.of("proxy", "repeater_history"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);

        SwingUtilities.invokeAndWait(() -> panel.onImportResult(imported));

        assertThat(repeaterHistoryCheckbox.isSelected()).isTrue();
    }

    private static ConfigPanel createPanel() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel(new ConfigController(new NoopUi()));
            panel.setSize(1000, 700);
            panel.doLayout();
            ref.set(panel);
        });
        return ref.get();
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {}
        @Override public void onOpenSearchStatus(String message) {}
        @Override public void onControlStatus(String message) {}
    }
}
