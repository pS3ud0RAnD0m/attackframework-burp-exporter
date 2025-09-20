package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.Json;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Headless test for {@link ConfigPanel} export behavior without file choosers or reflection.
 *
 * <p>Approach:
 * <ol>
 *   <li>Construct a panel and set explicit non-default values using visible UI controls.</li>
 *   <li>Click the "Save" button to trigger export; capture the emitted JSON via {@link Logger} listener.</li>
 *   <li>Parse the captured JSON with {@link Json#parseConfigJson(String)} and assert scope & sinks.</li>
 * </ol>
 *
 * <p>Notes:
 * <ul>
 *   <li>Import UI uses a {@code JFileChooser}; import-path integration is validated elsewhere (Json tests).
 *       This test focuses on export-through-UI correctness with no private access.</li>
 *   <li>All UI actions are executed on the EDT.</li>
 * </ul>
 */
class ConfigPanelImportExportHeadlessTest {

    @Test
    void export_via_save_logs_expected_json() throws Exception {
        // Arrange: construct panel and choose custom scope.
        ConfigPanel panel = new ConfigPanel();

        // Scope: select "Custom", set regex value, enable regex toggle.
        JRadioButton customRadio = findByName(panel, "scope.custom", JRadioButton.class);
        JTextField firstField = findByName(panel, "scope.custom.regex", JTextField.class);
        JCheckBox firstToggle = findRegexToggleForRow(firstField);

        String expectedRegex = "^(?:foo|bar)\\.example\\.com$";
        runEdt(() -> {
            customRadio.setSelected(true);
            firstToggle.setSelected(true);
            firstField.setText(expectedRegex);
        });

        // Sinks: enable files + os and set values.
        JCheckBox fileSink = findByName(panel, "files.enable", JCheckBox.class);
        JTextField filePath = findByName(panel, "files.path", JTextField.class);
        JCheckBox osSink = findByName(panel, "os.enable", JCheckBox.class);
        JTextField osUrl = findByName(panel, "os.url", JTextField.class);

        String expectedFilesPath = "c:/path/to/files";
        String expectedOsUrl = "http://opensearch.url:9200";

        runEdt(() -> {
            fileSink.setSelected(true);
            filePath.setText(expectedFilesPath);
            osSink.setSelected(true);
            osUrl.setText(expectedOsUrl);
        });

        // Capture export JSON via Logger when clicking "Save".
        CapturingListener cap = new CapturingListener();
        Logger.registerListener(cap);
        try {
            JButton save = findSaveButton(panel);
            runEdt(save::doClick);

            // The AdminSave handler logs a line with the JSON; capture the last well-formed JSON payload.
            String loggedJson = cap.lastJson();
            assertThat(loggedJson).as("save should log JSON").isNotBlank();

            Json.ImportedConfig cfg = Json.parseConfigJson(loggedJson);

            // Validate scope restored from JSON
            assertThat(cfg.scopeType()).as("scope type").isEqualTo("custom");
            assertThat(cfg.scopeRegexes()).isNotNull();
            assertThat(cfg.scopeRegexes()).isNotEmpty();
            assertThat(cfg.scopeRegexes().getFirst()).isEqualTo(expectedRegex);

            // Validate sinks restored from JSON
            assertThat(cfg.filesPath()).as("files path").isEqualTo(expectedFilesPath);
            assertThat(cfg.openSearchUrl()).as("os url").isEqualTo(expectedOsUrl);
        } finally {
            Logger.unregisterListener(cap);
        }
    }

    /* ----------------------------- helpers ----------------------------- */

    /** Logger listener that captures the most recent JSON-looking payload from INFO lines. */
    private static final class CapturingListener implements Logger.LogListener {
        private String lastJson = null;

        @Override
        public void onLog(String level, String message) {
            // We only care about INFO "json" lines; simple heuristic: looks like an object
            if (!"INFO".equalsIgnoreCase(level)) return;
            String m = message == null ? "" : message.trim();
            if (m.startsWith("{") && m.endsWith("}")) {
                lastJson = m;
            }
        }

        String lastJson() { return lastJson == null ? "" : lastJson; }
    }

    private static JButton findSaveButton(JComponent root) {
        // Traverse for a JButton with text "Save"
        List<JButton> all = new ArrayList<>();
        collect(root, JButton.class, all);
        for (JButton b : all) {
            if ("Save".equals(b.getText())) return b;
        }
        throw new AssertionError("Save button not found");
    }

    private static JCheckBox findRegexToggleForRow(JTextField fieldInRow) {
        var row = fieldInRow.getParent();
        for (var c : row.getComponents()) {
            if (c instanceof JCheckBox cb && ".*".equals(cb.getText())) return cb;
        }
        throw new AssertionError("Regex toggle (.*) not found in row");
    }

    private static <T extends JComponent> T findByName(JComponent root, String name, Class<T> type) {
        List<T> all = new ArrayList<>();
        collect(root, type, all);
        for (T c : all) {
            if (name.equals(c.getName())) return c;
        }
        throw new AssertionError("Component not found: " + name + " (" + type.getSimpleName() + ")");
    }

    private static <T extends JComponent> void collect(JComponent root, Class<T> type, List<T> out) {
        if (type.isInstance(root)) out.add(type.cast(root));
        for (var comp : root.getComponents()) {
            if (comp instanceof JComponent jc) collect(jc, type, out);
        }
    }

    /** Run the given action on the EDT and block until it completes. */
    private static void runEdt(Runnable action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeAndWait(action);
        }
    }
}
