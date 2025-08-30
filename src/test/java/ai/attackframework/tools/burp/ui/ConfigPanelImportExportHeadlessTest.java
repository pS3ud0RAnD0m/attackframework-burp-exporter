package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.config.Json;
import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static ai.attackframework.tools.burp.testutils.Reflect.call;
import static ai.attackframework.tools.burp.testutils.Reflect.callVoid;
import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies export/import round-trip for ConfigPanel configuration without using UI choosers.
 * Private members are accessed via the shared Reflect helper to keep production visibility minimal.
 */
class ConfigPanelImportExportHeadlessTest {

    @Test
    void export_then_import_roundtrip_with_custom_values() throws Exception {
        // Arrange a first panel with explicit, non-default values.
        ConfigPanel panel1 = new ConfigPanel();

        // Choose custom scope and set a regex value.
        JRadioButton customRadio1 = get(panel1, "customRadio");
        customRadio1.setSelected(true);

        JTextField customScopeField1 = get(panel1, "customScopeField");
        String expectedRegex = "^(?:foo|bar)\\.example\\.com$";
        customScopeField1.setText(expectedRegex);

        JCheckBox customScopeRegexToggle1 = get(panel1, "customScopeRegexToggle");
        customScopeRegexToggle1.setSelected(true);

        // Enable both sinks and set values.
        JCheckBox fileSinkCheckbox1 = get(panel1, "fileSinkCheckbox");
        fileSinkCheckbox1.setSelected(true);
        JTextField filePathField1 = get(panel1, "filePathField");
        String expectedFilesPath = "c:/path/to/files"; // textual value for JSON round-trip
        filePathField1.setText(expectedFilesPath);

        JCheckBox openSearchSinkCheckbox1 = get(panel1, "openSearchSinkCheckbox");
        openSearchSinkCheckbox1.setSelected(true);
        JTextField openSearchUrlField1 = get(panel1, "openSearchUrlField");
        String expectedOsUrl = "http://opensearch.url:9200";
        openSearchUrlField1.setText(expectedOsUrl);

        // Export to a temp JSON file by reflecting currentConfigJson() and writing it.
        Path tmpDir = Files.createTempDirectory("cfg-export-");
        Path out = tmpDir.resolve("config-roundtrip.json");
        String json = (String) call(panel1, "currentConfigJson");
        Files.writeString(out, json);

        assertThat(Files.exists(out)).as("exported config file should exist").isTrue();
        assertThat(Files.size(out)).as("exported config should not be empty").isGreaterThan(0L);

        // Import into a fresh panel by parsing JSON and reflecting applyImported(...).
        ConfigPanel panel2 = new ConfigPanel();
        String imported = Files.readString(out);
        Json.ImportedConfig cfg = Json.parseConfigJson(imported);
        callVoid(panel2, "applyImported", cfg);
        // Mirror non-UI side-effects of the old import helper.
        callVoid(panel2, "refreshEnabledStates");
        callVoid(panel2, "updateCustomRegexFeedback");

        // Validate scope restored.
        JRadioButton customRadio2 = get(panel2, "customRadio");
        assertThat(customRadio2.isSelected()).as("custom scope radio restored").isTrue();

        JTextField customScopeField2 = get(panel2, "customScopeField");
        assertThat(customScopeField2.getText()).as("custom scope value restored").isEqualTo(expectedRegex);

        // Note: current import logic restores the value, not the regex/string kind toggle.
        // Verify the toggle defaults to unchecked here; when import supports kinds, this can be tightened.
        @SuppressWarnings("unchecked")
        List<JCheckBox> toggles2 = get(panel2, "customScopeRegexToggles");
        assertThat(toggles2.getFirst().isSelected()).as("regex toggle defaults unchecked on import").isFalse();

        // Validate sinks restored.
        JCheckBox fileSinkCheckbox2 = get(panel2, "fileSinkCheckbox");
        assertThat(fileSinkCheckbox2.isSelected()).as("file sink restored").isTrue();
        JTextField filePathField2 = get(panel2, "filePathField");
        assertThat(filePathField2.getText()).as("files path restored").isEqualTo(expectedFilesPath);

        JCheckBox openSearchSinkCheckbox2 = get(panel2, "openSearchSinkCheckbox");
        assertThat(openSearchSinkCheckbox2.isSelected()).as("OpenSearch sink restored").isTrue();
        JTextField openSearchUrlField2 = get(panel2, "openSearchUrlField");
        assertThat(openSearchUrlField2.getText()).as("OpenSearch URL restored").isEqualTo(expectedOsUrl);
    }
}
