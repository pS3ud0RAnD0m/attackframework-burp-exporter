package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.Container;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Import/Export round-trip without choosers, using stable component names.
 * Focus is on behavior (state flows through JSON), not on UI labels.
 */
public class ConfigPanelImportExportHeadlessTest {

    @Test
    void export_then_import_roundtrip_with_custom_values() throws Exception {
        // Arrange initial panel with customized values
        ConfigPanel panel1 = new ConfigPanel();

        // Select Custom scope and set a custom regex
        JRadioButton custom = (JRadioButton) findByName(panel1, "scope.custom");
        assertNotNull(custom, "Custom scope radio not found");
        custom.setSelected(true);

        JTextField regexField = (JTextField) findByName(panel1, "scope.custom.regex");
        assertNotNull(regexField, "Custom regex field not found");
        regexField.setText("^(foo|bar)\\.example$");

        // Enable OpenSearch and set URL
        JCheckBox openSearchCb = (JCheckBox) findByName(panel1, "os.enable");
        assertNotNull(openSearchCb, "OpenSearch checkbox not found");
        openSearchCb.setSelected(true);

        JTextField osUrl = (JTextField) findByName(panel1, "os.url");
        assertNotNull(osUrl, "OpenSearch URL field not found");
        osUrl.setText("http://localhost:9200");

        // Enable Files (default is true) and set a temp path
        JCheckBox filesCb = (JCheckBox) findByName(panel1, "files.enable");
        assertNotNull(filesCb, "Files checkbox not found");
        filesCb.setSelected(true);

        Path tmpDir = Files.createTempDirectory("af-burp-roundtrip-");
        JTextField filesPath = (JTextField) findByName(panel1, "files.path");
        assertNotNull(filesPath, "Files path field not found");
        filesPath.setText(tmpDir.toString());

        // Export to temp file
        Path out = Files.createTempFile("af-burp-roundtrip-", ".json");
        panel1.exportConfigTo(out);

        // Import into a fresh panel
        ConfigPanel panel2 = new ConfigPanel();
        panel2.importConfigFrom(out);

        // Assert scope + regex
        JRadioButton custom2 = (JRadioButton) findByName(panel2, "scope.custom");
        assertNotNull(custom2, "Custom scope radio missing after import");
        assertTrue(custom2.isSelected(), "Custom scope should be selected after import");

        JTextField regexField2 = (JTextField) findByName(panel2, "scope.custom.regex");
        assertNotNull(regexField2, "Imported custom regex field missing");
        assertEquals("^(foo|bar)\\.example$", regexField2.getText(), "Imported regex should match");

        // Assert sinks
        JCheckBox filesCb2 = (JCheckBox) findByName(panel2, "files.enable");
        assertNotNull(filesCb2, "Files checkbox missing after import");
        assertTrue(filesCb2.isSelected(), "Files sink should be enabled");

        JTextField filesPath2 = (JTextField) findByName(panel2, "files.path");
        assertNotNull(filesPath2, "Imported files path field missing");
        assertEquals(tmpDir.toString(), filesPath2.getText(), "Imported files path should match");

        JCheckBox openSearchCb2 = (JCheckBox) findByName(panel2, "os.enable");
        assertNotNull(openSearchCb2, "OpenSearch checkbox missing after import");
        assertTrue(openSearchCb2.isSelected(), "OpenSearch sink should be enabled");

        JTextField osUrl2 = (JTextField) findByName(panel2, "os.url");
        assertNotNull(osUrl2, "Imported OpenSearch URL field missing");
        assertEquals("http://localhost:9200", osUrl2.getText(), "Imported OpenSearch URL should match");
    }

    // ---- component finders by stable name ----

    private static Component findByName(Container root, String name) {
        for (Component c : getAll(root)) {
            if (name.equals(c.getName())) {
                return c;
            }
        }
        return null;
    }

    private static List<Component> getAll(Component root) {
        List<Component> all = new ArrayList<>();
        collect(root, all);
        return all;
    }

    private static void collect(Component c, List<Component> out) {
        out.add(c);
        if (c instanceof Container cont) {
            for (Component child : cont.getComponents()) {
                collect(child, out);
            }
        }
    }
}
