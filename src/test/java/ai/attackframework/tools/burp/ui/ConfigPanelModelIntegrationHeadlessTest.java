package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigState;
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
 * End-to-end model integration:
 * UI (panel A) -> mapper.build(JSON) -> mapper.parse(typed) -> UI (panel B),
 * verifying that the second panel produces the same JSON via Save.
 */
class ConfigPanelModelIntegrationHeadlessTest {

    @Test
    void ui_to_json_to_state_back_to_ui_roundtrip() throws Exception {
        // ---- Panel A: set UI via visible controls ----
        ConfigPanel a = new ConfigPanel();

        // Sources
        JCheckBox settings = findByName(a, "src.settings", JCheckBox.class);
        JCheckBox sitemap  = findByName(a, "src.sitemap", JCheckBox.class);

        // Scope (custom)
        JRadioButton custom = findByName(a, "scope.custom", JRadioButton.class);
        JTextField firstField = findByName(a, "scope.custom.regex", JTextField.class);
        JCheckBox firstToggle = findRegexToggleForRow(firstField);

        // Sinks
        JCheckBox filesEnable = findByName(a, "files.enable", JCheckBox.class);
        JTextField filesPath  = findByName(a, "files.path", JTextField.class);
        JCheckBox osEnable    = findByName(a, "os.enable", JCheckBox.class);
        JTextField osUrl      = findByName(a, "os.url", JTextField.class);

        runEdt(() -> {
            settings.setSelected(true);
            sitemap.setSelected(true);

            custom.setSelected(true);
            firstToggle.setSelected(true);
            firstField.setText("^foo$");

            filesEnable.setSelected(true);
            filesPath.setText("/tmp/af");
            osEnable.setSelected(true);
            osUrl.setText("http://opensearch.url:9200");
        });

        // Capture JSON produced by Save on panel A
        String jsonA = captureJsonViaSave(a);
        assertThat(jsonA).isNotBlank();

        // ---- Mapper.parse(JSON) -> typed state ----
        ConfigState.State state = ConfigJsonMapper.parse(jsonA);
        assertThat(state.scopeType()).isEqualTo("custom");

        // ---- Panel B: apply typed state via visible controls ----
        ConfigPanel b = new ConfigPanel();

        JCheckBox settingsB = findByName(b, "src.settings", JCheckBox.class);
        JCheckBox sitemapB  = findByName(b, "src.sitemap", JCheckBox.class);
        JRadioButton customB = findByName(b, "scope.custom", JRadioButton.class);
        JTextField firstFieldB = findByName(b, "scope.custom.regex", JTextField.class);
        JCheckBox firstToggleB = findRegexToggleForRow(firstFieldB);
        JCheckBox filesEnableB = findByName(b, "files.enable", JCheckBox.class);
        JTextField filesPathB  = findByName(b, "files.path", JTextField.class);
        JCheckBox osEnableB    = findByName(b, "os.enable", JCheckBox.class);
        JTextField osUrlB      = findByName(b, "os.url", JTextField.class);

        runEdt(() -> {
            // sources
            settingsB.setSelected(state.dataSources().contains("settings"));
            sitemapB.setSelected(state.dataSources().contains("sitemap"));

            // scope
            switch (state.scopeType()) {
                case "custom" -> {
                    customB.setSelected(true);
                    if (!state.customEntries().isEmpty()) {
                        var e = state.customEntries().getFirst();
                        firstFieldB.setText(e.value());
                        firstToggleB.setSelected(e.kind() != ConfigState.Kind.STRING);
                    }
                }
                case "burp" -> findByName(b, "scope.burp", JRadioButton.class).setSelected(true);
                default     -> findByName(b, "scope.all", JRadioButton.class).setSelected(true);
            }

            // sinks
            filesEnableB.setSelected(state.sinks().filesEnabled());
            filesPathB.setText(state.sinks().filesPath() == null ? "" : state.sinks().filesPath());
            osEnableB.setSelected(state.sinks().osEnabled());
            osUrlB.setText(state.sinks().openSearchUrl() == null ? "" : state.sinks().openSearchUrl());
        });

        // Capture JSON produced by Save on panel B and compare
        String jsonB = captureJsonViaSave(b);
        assertThat(jsonB).isEqualTo(jsonA);
    }

    /* ----------------------------- helpers ----------------------------- */

    private static String captureJsonViaSave(ConfigPanel p) throws Exception {
        JButton save = findSaveButton(p);
        CapturingListener cap = new CapturingListener();
        Logger.registerListener(cap);
        try {
            runEdt(save::doClick);
            String out = cap.lastJson();
            assertThat(out).as("Save should log JSON").isNotBlank();
            return out;
        } finally {
            Logger.unregisterListener(cap);
        }
    }

    private static JButton findSaveButton(JComponent root) {
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

    private static void runEdt(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }

    /** Logger listener capturing the last JSON payload logged by Save. */
    private static final class CapturingListener implements Logger.LogListener {
        private String lastJson = null;
        @Override public void onLog(String level, String message) {
            if (!"INFO".equalsIgnoreCase(level)) return;
            String m = message == null ? "" : message.trim();
            if (m.startsWith("{") && m.endsWith("}")) lastJson = m;
        }
        String lastJson() { return lastJson == null ? "" : lastJson; }
    }
}
