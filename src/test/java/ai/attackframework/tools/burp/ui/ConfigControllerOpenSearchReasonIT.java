package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.sinks.OpenSearchSink;
import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Verifies that createIndexesAsync appends a concise "Reason: ..." line on failure. */
class ConfigControllerOpenSearchReasonIT {

    @Test
    void createIndexes_failed_includes_reason_line() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        CapturingUi ui = new CapturingUi(done);
        ConfigController controller = controllerForFailure(ui);

        controller.createIndexesAsync("http://opensearch.url:9200", List.of("settings", "sitemap"));

        assertTrue(done.await(Duration.ofSeconds(5).toMillis(), TimeUnit.MILLISECONDS), "Timed out waiting for status");

        String status = ui.lastOpenSearchStatus;
        assertNotNull(status, "Expected an OpenSearch status message");
        assertTrue(status.contains("Indexes failed:"), "Expected header listing failed indexes");
        assertTrue(status.contains("attackframework-tool-burp-settings"), "Expected settings index in list");
        assertTrue(status.contains("attackframework-tool-burp-sitemap"), "Expected sitemap index in list");
        assertTrue(status.contains("Reason:"), "Expected a concise reason line");
        assertTrue(status.contains("Connection refused"), "Expected the raw error in reason line");
    }

    private static ConfigController controllerForFailure(ConfigController.Ui ui) {
        ConfigController.OpenSearchPorts os = new ConfigController.OpenSearchPorts() {
            @Override
            public ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper.OpenSearchStatus testConnection(String url) {
                throw new UnsupportedOperationException("not used");
            }
            @Override
            public List<OpenSearchSink.IndexResult> createSelectedIndexes(String url, List<String> selectedSources) {
                List<OpenSearchSink.IndexResult> out = new ArrayList<>();
                out.add(new OpenSearchSink.IndexResult("settings", "attackframework-tool-burp-settings",
                        OpenSearchSink.IndexResult.Status.FAILED,
                        "Connect to http://opensearch.url:9200 [opensearch.url/127.0.0.1] failed: Connection refused: getsockopt"));
                out.add(new OpenSearchSink.IndexResult("sitemap", "attackframework-tool-burp-sitemap",
                        OpenSearchSink.IndexResult.Status.FAILED,
                        "Connect to http://opensearch.url:9200 [opensearch.url/127.0.0.1] failed: Connection refused: getsockopt"));
                return out;
            }
        };

        ConfigController.FilePorts files = new ConfigController.FilePorts() {
            @Override public List<FileUtil.CreateResult> ensureJsonFiles(String root, List<String> jsonNames) { return List.of(); }
            @Override public void writeStringCreateDirs(Path out, String content) { /* no-op */ }
            @Override public String readString(Path in) { return ""; }
        };

        ConfigController.IndexNamingPorts naming = new ConfigController.IndexNamingPorts() {
            @Override public List<String> computeIndexBaseNames(List<String> selectedSources) { return selectedSources; }
            @Override public List<String> toJsonFileNames(List<String> baseNames) { return baseNames; }
        };

        return new ConfigController(ui, files, os, naming);
    }

    /* ---------- minimal UI capture harness ---------- */
    private static final class CapturingUi implements ConfigController.Ui {
        volatile String lastOpenSearchStatus;
        private final CountDownLatch done;
        CapturingUi(CountDownLatch done) { this.done = done; }

        @Override public void onFileStatus(String message) { /* not used */ }
        @Override public void onOpenSearchStatus(String message) {
            lastOpenSearchStatus = message;
            if (message.contains("Indexes failed:") || message.contains("Index failed:")) {
                done.countDown();
            }
        }
        @Override public void onAdminStatus(String message) { /* not used */ }
        @Override public void onImportResult(ConfigState.State state) { /* not used */ }
    }
}
