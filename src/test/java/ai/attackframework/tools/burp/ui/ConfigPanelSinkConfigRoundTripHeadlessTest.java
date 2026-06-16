package ai.attackframework.tools.burp.ui;

import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.testutils.Reflect.call;
import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static ai.attackframework.tools.burp.testutils.Reflect.getComboBox;
import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.config.SecureCredentialStore;

class ConfigPanelSinkConfigRoundTripHeadlessTest {

    @Test
    void export_and_import_roundTrip_preserves_nested_sink_shape_from_ui_state() throws Exception {
        withCleanSession(() -> {
            ConfigPanel original = newPanelOnEdt();

            JCheckBox fileSinkCheckbox = JCheckBox.class.cast(get(original, "fileSinkCheckbox"));
            JTextField filePathField = JTextField.class.cast(get(original, "filePathField"));
            JRadioButton fileJsonlCheckbox = JRadioButton.class.cast(get(original, "fileJsonlCheckbox"));
            JCheckBox fileTotalCapCheckbox = JCheckBox.class.cast(get(original, "fileTotalCapCheckbox"));
            JTextField fileTotalCapField = JTextField.class.cast(get(original, "fileTotalCapField"));
            JCheckBox fileDiskUsagePercentCheckbox = JCheckBox.class.cast(get(original, "fileDiskUsagePercentCheckbox"));
            JTextField fileDiskUsagePercentField = JTextField.class.cast(get(original, "fileDiskUsagePercentField"));
            JCheckBox openSearchSinkCheckbox = JCheckBox.class.cast(get(original, "openSearchSinkCheckbox"));
            JTextField openSearchUrlField = JTextField.class.cast(get(original, "openSearchUrlField"));
            JComboBox<String> openSearchAuthTypeCombo = getComboBox(original, "openSearchAuthTypeCombo");
            JTextField openSearchUserField = JTextField.class.cast(get(original, "openSearchUserField"));
            JTextField openSearchCertPathField = JTextField.class.cast(get(original, "openSearchCertPathField"));
            JTextField openSearchCertKeyPathField = JTextField.class.cast(get(original, "openSearchCertKeyPathField"));
            JComboBox<String> openSearchTlsModeCombo = getComboBox(original, "openSearchTlsModeCombo");

            runEdt(() -> {
                if (!fileSinkCheckbox.isSelected()) {
                    fileSinkCheckbox.doClick();
                }
                filePathField.setText("C:/Burp/ui-roundtrip");
                if (!fileJsonlCheckbox.isSelected()) {
                    fileJsonlCheckbox.doClick();
                }
                if (fileTotalCapCheckbox.isSelected()) {
                    fileTotalCapCheckbox.doClick();
                }
                fileTotalCapField.setText("12.5");
                if (!fileDiskUsagePercentCheckbox.isSelected()) {
                    fileDiskUsagePercentCheckbox.doClick();
                }
                fileDiskUsagePercentField.setText("88");

                if (!openSearchSinkCheckbox.isSelected()) {
                    openSearchSinkCheckbox.doClick();
                }
                openSearchUrlField.setText("https://opensearch.example:9200");
                openSearchUserField.setText("stale-user");
                openSearchAuthTypeCombo.setSelectedItem("Certificate");
                openSearchCertPathField.setText("certs/client.pem");
                openSearchCertKeyPathField.setText("certs/client-key.pem");
                openSearchTlsModeCombo.setSelectedItem("Trust all certificates");
            });

            ConfigState.State originalState = (ConfigState.State) call(original, "buildCurrentState");
            String json = ConfigJsonMapper.build(originalState);

            assertThat(json).contains("\"sinks\" : {");
            assertThat(json).contains("\"files\" : {");
            assertThat(json).contains("\"openSearch\" : {");
            assertThat(json).contains("\"formats\" : [ \"jsonl\" ]");
            assertThat(json).contains("\"tlsMode\" : \"insecure\"");
            assertThat(json).contains("\"type\" : \"Certificate\"");
            assertThat(json).contains("\"certPath\" : \"certs/client.pem\"");
            assertThat(json).contains("\"certKeyPath\" : \"certs/client-key.pem\"");
            assertThat(json).doesNotContain("\"filesEnabled\"");
            assertThat(json).doesNotContain("\"openSearchEnabled\"");
            assertThat(json).doesNotContain("\"username\" : \"stale-user\"");

            ConfigState.State imported = ConfigJsonMapper.parseState(json);

            SecureCredentialStore.clearAll();
            RuntimeConfig.updateState(null);

            ConfigPanel restored = newPanelOnEdt();
            runEdt(() -> restored.onImportResult(imported));

            JTextField restoredFilePathField = JTextField.class.cast(get(restored, "filePathField"));
            JComboBox<String> restoredAuthTypeCombo = getComboBox(restored, "openSearchAuthTypeCombo");
            JTextField restoredOpenSearchUserField = JTextField.class.cast(get(restored, "openSearchUserField"));
            JTextField restoredCertPathField = JTextField.class.cast(get(restored, "openSearchCertPathField"));
            JTextField restoredCertKeyPathField = JTextField.class.cast(get(restored, "openSearchCertKeyPathField"));
            JComboBox<String> restoredTlsModeCombo = getComboBox(restored, "openSearchTlsModeCombo");

            runEdt(() -> {
                assertThat(restoredFilePathField.getText()).isEqualTo("C:/Burp/ui-roundtrip");
                assertThat(String.valueOf(restoredAuthTypeCombo.getSelectedItem())).isEqualTo("Certificate");
                assertThat(restoredOpenSearchUserField.getText()).isEmpty();
                assertThat(restoredCertPathField.getText()).isEqualTo("certs/client.pem");
                assertThat(restoredCertKeyPathField.getText()).isEqualTo("certs/client-key.pem");
                assertThat(String.valueOf(restoredTlsModeCombo.getSelectedItem())).isEqualTo("Trust all certificates");
            });

            ConfigState.State restoredState = (ConfigState.State) call(restored, "buildCurrentState");
            assertThat(restoredState.sinks().filesEnabled()).isTrue();
            assertThat(restoredState.sinks().filesPath()).isEqualTo("C:/Burp/ui-roundtrip");
            assertThat(restoredState.sinks().fileJsonlEnabled()).isTrue();
            assertThat(restoredState.sinks().fileBulkNdjsonEnabled()).isFalse();
            assertThat(restoredState.sinks().fileTotalCapEnabled()).isFalse();
            assertThat(restoredState.sinks().fileTotalCapGb()).isEqualTo(12.5d);
            assertThat(restoredState.sinks().fileDiskUsagePercentEnabled()).isTrue();
            assertThat(restoredState.sinks().fileDiskUsagePercent()).isEqualTo(88);
            assertThat(restoredState.sinks().osEnabled()).isTrue();
            assertThat(restoredState.sinks().openSearchUrl()).isEqualTo("https://opensearch.example:9200");
            assertThat(restoredState.sinks().openSearchUser()).isBlank();
            assertThat(restoredState.sinks().openSearchTlsMode()).isEqualTo(ConfigState.OPEN_SEARCH_TLS_INSECURE);
            assertThat(restoredState.sinks().openSearchOptions().authType()).isEqualTo("Certificate");
            assertThat(restoredState.sinks().openSearchOptions().certPath()).isEqualTo("certs/client.pem");
            assertThat(restoredState.sinks().openSearchOptions().certKeyPath()).isEqualTo("certs/client-key.pem");
        });
    }

    private static ConfigPanel newPanelOnEdt() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel(new ConfigController(new NoopUi()));
            panel.setSize(1000, 700);
            panel.doLayout();
            ref.set(panel);
        });
        return ref.get();
    }

    private static void runEdt(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }

    private static void withCleanSession(CheckedRunnable action) throws Exception {
        SecureCredentialStore.clearAll();
        RuntimeConfig.updateState(null);
        try {
            action.run();
        } finally {
            SecureCredentialStore.clearAll();
            RuntimeConfig.updateState(null);
        }
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) { }
        @Override public void onOpenSearchStatus(String message) { }
        @Override public void onControlStatus(String message) { }
    }
}
