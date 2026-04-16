package ai.attackframework.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.Reflect;
import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;

class ConfigPanelExporterHeadlessTest {

    @Test
    void exporterSource_defaultsEnabled_withStatsIntervalAndToolFieldsSection() throws Exception {
        ConfigPanel panel = createPanel();

        JCheckBox exporterCheckbox = Reflect.get(panel, "exporterCheckbox");
        JCheckBox exporterStatsCheckbox = Reflect.get(panel, "exporterStatsCheckbox");
        JTextField exporterStatsIntervalField = Reflect.get(panel, "exporterStatsIntervalField");
        Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");

        ConfigState.State state = (ConfigState.State) Reflect.call(panel, "buildCurrentState");

        assertThat(exporterCheckbox.isSelected()).isTrue();
        assertThat(exporterCheckbox.getToolTipText()).contains("Burp Exporter runtime telemetry");
        assertThat(exporterStatsCheckbox.isSelected()).isTrue();
        assertThat(exporterStatsIntervalField.getText()).isEqualTo("30");
        assertThat(headerRows).containsKey("tool");
        assertThat(state.dataSources()).contains(ConfigKeys.SRC_EXPORTER);
        assertThat(state.exporterSubOptions()).contains(
                ConfigKeys.SRC_EXPORTER_INFO,
                ConfigKeys.SRC_EXPORTER_STATS,
                ConfigKeys.SRC_EXPORTER_CONFIG);
        assertThat(state.exporterStatsIntervalSeconds()).isEqualTo(30);
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
