package ai.attackframework.tools.burp.ui;

import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JComponent;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.testutils.Reflect.call;
import static ai.attackframework.tools.burp.testutils.Reflect.get;
import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;

/**
 * Verifies that toggling destination checkboxes enables/disables the corresponding
 * text fields and action buttons.
 */
@SuppressWarnings("unused")
class ConfigPanelDestinationEnablementHeadlessTest {

    private ConfigPanel panel;

    @BeforeEach
    @SuppressWarnings("unused")
    void setup() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel p = new ConfigPanel(new ConfigController(new NoopUi()));
            if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                p.setSize(1000, 700);
            }
            p.doLayout();
            ref.set(p);
        });
        panel = ref.get();
    }

    @Test
    void deselecting_destinations_disables_textfields_and_action_buttons() {
        // Files row (access private fields directly via shared Reflect helper).
        JCheckBox filesEnable = get(panel, "fileSinkCheckbox");
        JRadioButton jsonlEnable = get(panel, "fileJsonlCheckbox");
        JRadioButton bulkNdjsonEnable = get(panel, "fileBulkNdjsonCheckbox");
        JTextField filesPath  = get(panel, "filePathField");
        JCheckBox totalEnable = get(panel, "fileTotalCapCheckbox");
        JTextField totalField = get(panel, "fileTotalCapField");
        JCheckBox diskPercentEnable = get(panel, "fileDiskUsagePercentCheckbox");
        JTextField diskPercentField = get(panel, "fileDiskUsagePercentField");

        // OpenSearch row
        JCheckBox osEnable  = get(panel, "openSearchSinkCheckbox");
        JTextField osUrl    = get(panel, "openSearchUrlField");
        JComboBox<?> osAuthType = get(panel, "openSearchAuthTypeCombo");
        JComboBox<?> osTlsMode = get(panel, "openSearchTlsModeCombo");
        JButton osTest      = get(panel, "testConnectionButton");

        // Ensure both destinations are enabled
        if (!filesEnable.isSelected()) filesEnable.doClick();
        if (!bulkNdjsonEnable.isSelected()) bulkNdjsonEnable.doClick();
        if (!osEnable.isSelected()) osEnable.doClick();

        // Enabled assertions
        assertThat(filesPath.isEnabled()).isTrue();
        assertThat(jsonlEnable.isEnabled()).isTrue();
        assertThat(bulkNdjsonEnable.isEnabled()).isTrue();
        assertThat(totalEnable.isEnabled()).isTrue();
        assertThat(totalField.isEnabled()).isTrue();
        assertThat(diskPercentEnable.isEnabled()).isTrue();
        assertThat(diskPercentField.isEnabled()).isTrue();
        assertThat(osUrl.isEnabled()).isTrue();
        assertThat(osAuthType.isEnabled()).isTrue();
        assertThat(osTlsMode.isEnabled()).isTrue();
        assertThat(osTest.isEnabled()).isTrue();

        // Disable both destinations
        if (filesEnable.isSelected()) filesEnable.doClick();
        if (osEnable.isSelected()) osEnable.doClick();

        // Disabled assertions
        assertThat(filesPath.isEnabled()).isFalse();
        assertThat(jsonlEnable.isEnabled()).isFalse();
        assertThat(bulkNdjsonEnable.isEnabled()).isFalse();
        assertThat(totalEnable.isEnabled()).isFalse();
        assertThat(totalField.isEnabled()).isFalse();
        assertThat(diskPercentEnable.isEnabled()).isFalse();
        assertThat(diskPercentField.isEnabled()).isFalse();
        assertThat(osUrl.isEnabled()).isFalse();
        assertThat(osAuthType.isEnabled()).isFalse();
        assertThat(osTlsMode.isEnabled()).isFalse();
        assertThat(osTest.isEnabled()).isFalse();
    }

    @Test
    void file_format_tooltips_expand_jsonl_and_ndjson_terms() {
        JRadioButton jsonlEnable = get(panel, "fileJsonlCheckbox");
        JRadioButton bulkNdjsonEnable = get(panel, "fileBulkNdjsonCheckbox");

        assertThat(jsonlEnable.getText()).isEqualTo("JSONL");
        assertThat(bulkNdjsonEnable.getText()).isEqualTo("NDJSON");
        assertThat(jsonlEnable.getToolTipText()).contains("JSON Lines");
        assertThat(jsonlEnable.getToolTipText()).contains("standalone JSON object");
        assertThat(bulkNdjsonEnable.getToolTipText()).contains("Newline-Delimited JSON");
        assertThat(bulkNdjsonEnable.getToolTipText()).contains("_bulk");
        assertThat(bulkNdjsonEnable.getToolTipText()).contains("two lines");
    }

    @Test
    void file_format_radios_default_to_bulk_ndjson_and_allow_only_one_selection() {
        JCheckBox filesEnable = get(panel, "fileSinkCheckbox");
        JRadioButton jsonlEnable = get(panel, "fileJsonlCheckbox");
        JRadioButton bulkNdjsonEnable = get(panel, "fileBulkNdjsonCheckbox");

        if (!filesEnable.isSelected()) {
            filesEnable.doClick();
        }

        assertThat(jsonlEnable.isSelected()).isFalse();
        assertThat(bulkNdjsonEnable.isSelected()).isTrue();

        jsonlEnable.doClick();
        assertThat(jsonlEnable.isSelected()).isTrue();
        assertThat(bulkNdjsonEnable.isSelected()).isFalse();

        bulkNdjsonEnable.doClick();
        assertThat(jsonlEnable.isSelected()).isFalse();
        assertThat(bulkNdjsonEnable.isSelected()).isTrue();
    }

    @Test
    void file_total_cap_field_accepts_decimal_gib_and_round_trips_cleanly() throws Exception {
        JTextField totalField = get(panel, "fileTotalCapField");

        SwingUtilities.invokeAndWait(() -> {
            totalField.setText("1.25");
        });

        ConfigState.State current = (ConfigState.State) call(panel, "buildCurrentState");
        assertThat(current.sinks().fileTotalCapBytes()).isEqualTo(1_342_177_280L);

        ConfigState.State imported = new ConfigState.State(
                java.util.List.of(),
                ConfigKeys.SCOPE_ALL,
                java.util.List.of(),
                new ConfigState.Sinks(true, "/path/to/directory", false, true,
                        true, 1_342_177_280L,
                        true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false, "", "", "", ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        SwingUtilities.invokeAndWait(() -> panel.onImportResult(imported));

        assertThat(totalField.getText()).isEqualTo("1.25");
    }

    @Test
    void per_index_cap_controls_are_not_present() {
        assertThat(findByName(panel, "files.limit.perIndex.enable")).isNull();
        assertThat(findByName(panel, "files.limit.perIndex.gib")).isNull();
    }

    @Test
    void pinned_tls_mode_shows_import_button_only_when_selected() {
        JComboBox<String> tlsMode = get(panel, "openSearchTlsModeCombo");
        JButton importButton = get(panel, "importPinnedCertificateButton");

        assertThat(importButton.isVisible()).isFalse();

        tlsMode.setSelectedItem("Trust pinned certificate");
        assertThat(importButton.isVisible()).isTrue();

        tlsMode.setSelectedItem("Verify");
        assertThat(importButton.isVisible()).isFalse();
    }

    private static JComponent findByName(JComponent root, String name) {
        String componentName = root.getName();
        if (componentName != null && componentName.equals(name)) {
            return root;
        }
        for (java.awt.Component component : root.getComponents()) {
            if (component instanceof JComponent child) {
                JComponent nested = findByName(child, name);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {
            // File status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onOpenSearchStatus(String message) {
            // OpenSearch status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onControlStatus(String message) {
            // Control status is not observed in this test; required by ConfigController.Ui
        }
    }
}
