package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.testutils.Reflect;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JTextField;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Headless verification that {@link ConfigPanel} delegates actions to {@link ConfigController}.
 *
 * <p>We do not change production code: this test swaps the private {@code controller} field via
 * the shared {@link Reflect} helper and injects a fake that records invocations.</p>
 */
class ConfigPanelDelegationHeadlessTest {

    private static final int TIMEOUT_SECONDS = 4;

    @Test
    void clicking_buttons_invokes_controller_methods_and_updates_status() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        // Minimal inputs so handlers run without early exits
        JCheckBox filesEnable = findByName(panel, "files.enable", JCheckBox.class);
        JTextField pathField = findByName(panel, "files.path", JTextField.class);
        filesEnable.setSelected(true);
        pathField.setText("/tmp/af");

        AtomicBoolean createFilesCalled = new AtomicBoolean(false);
        AtomicBoolean testConnCalled = new AtomicBoolean(false);
        AtomicBoolean createIdxCalled = new AtomicBoolean(false);

        CountDownLatch fileLatch = new CountDownLatch(1);
        CountDownLatch osLatch1 = new CountDownLatch(1);
        CountDownLatch osLatch2 = new CountDownLatch(1);

        // Fake ports: flip flags and push canned status into the panel UI callbacks
        ConfigController.FilePorts filePorts = new ConfigController.FilePorts() {
            @Override
            public List<ai.attackframework.tools.burp.utils.FileUtil.CreateResult> ensureJsonFiles(
                    String root, List<String> jsonNames) {
                createFilesCalled.set(true);
                panel.onFileStatus("ok");
                fileLatch.countDown();
                return List.of();
            }
            @Override public void writeStringCreateDirs(Path out, String content) { /* not used here */ }
            @Override public String readString(Path in) { return ""; }
        };

        ConfigController.OpenSearchPorts osPorts = new ConfigController.OpenSearchPorts() {
            @Override
            public ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper.OpenSearchStatus
            testConnection(String url) {
                testConnCalled.set(true);
                panel.onOpenSearchStatus("OK");
                osLatch1.countDown();
                return new ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper
                        .OpenSearchStatus(true, "OK", "dist", "0");
            }
            @Override
            public List<ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult>
            createSelectedIndexes(String url, List<String> selectedSources) {
                createIdxCalled.set(true);
                panel.onOpenSearchStatus("OK");
                osLatch2.countDown();
                return List.of();
            }
        };

        ConfigController.IndexNamingPorts namingPorts = new ConfigController.IndexNamingPorts() {
            @Override public List<String> computeIndexBaseNames(List<String> selectedSources) { return List.of("a"); }
            @Override public List<String> toJsonFileNames(List<String> baseNames) { return List.of("a.json"); }
        };

        // Inject fake controller (no production changes)
        ConfigController fake = new ConfigController(panel, filePorts, osPorts, namingPorts);
        Reflect.set(panel, "controller", fake);

        // Click Create Files
        JButton createFiles = findByName(panel, "files.create", JButton.class);
        createFiles.doClick();
        assertThat(fileLatch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();
        assertThat(createFilesCalled.get()).isTrue();

        // Click Test Connection
        JButton testConn = findByName(panel, "os.test", JButton.class);
        findByName(panel, "os.enable", JCheckBox.class).setSelected(true);
        findByName(panel, "os.url", JTextField.class).setText("http://x");
        testConn.doClick();
        assertThat(osLatch1.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();
        assertThat(testConnCalled.get()).isTrue();

        // Click Create Indexes
        JButton createIdx = findByName(panel, "os.createIndexes", JButton.class);
        createIdx.doClick();
        assertThat(osLatch2.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();
        assertThat(createIdxCalled.get()).isTrue();
    }

    /* ----------------------------- helpers ----------------------------- */

    private static <T extends JComponent> T findByName(JComponent root, String name, Class<T> type) {
        List<T> all = new ArrayList<>();
        collect(root, type, all);
        for (T c : all) if (name.equals(c.getName())) return c;
        throw new AssertionError("Component not found: " + name + " (" + type.getSimpleName() + ")");
    }

    private static <T extends JComponent> void collect(JComponent root, Class<T> type, List<T> out) {
        if (type.isInstance(root)) out.add(type.cast(root));
        for (var comp : root.getComponents()) {
            if (comp instanceof JComponent jc) collect(jc, type, out);
        }
    }
}
