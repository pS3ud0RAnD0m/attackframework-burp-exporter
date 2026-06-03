package ai.attackframework.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.ControlStatusBridge;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

@Tag("integration")
class IndexingRetryCoordinatorFailureShutdownIT {

    @Test
    void repeatedAuthFailures_disableOpenSearch_and_keepFilesDestinationRunning() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        ConfigState.State previous = RuntimeConfig.getState();
        Path exportRoot = TestPathSupport.createDirectory("disable-opensearch-runtime");
        String indexName = "af-disable-opensearch-" + Instant.now().toEpochMilli();
        AtomicReference<String> status = new AtomicReference<>();
        try {
            OpenSearchReachable.getClient().indices().create(new CreateIndexRequest.Builder().index(indexName).build());
            ControlStatusBridge.register(status::set);
            IndexingRetryCoordinator.getInstance().clearPendingWork();
            RuntimeConfig.updateState(stateWithDestinations(exportRoot, true));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);

            for (int i = 0; i < 3; i++) {
                IndexingRetryCoordinator.getInstance().pushDocument(OpenSearchReachable.BASE_URL, indexName, sampleDoc(i), "exporter");
            }

            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.isAnyFileExportEnabled()).isTrue();
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files");
            assertThat(status.get()).contains("OpenSearch export disabled after repeated authentication failures");
            assertThat(status.get()).contains("Files export will continue");
        } finally {
            ControlStatusBridge.clear();
            IndexingRetryCoordinator.getInstance().clearPendingWork();
            RuntimeConfig.updateState(previous);
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportStarting(false);
            ExportReporterLifecycle.resetForTests();
            try {
                OpenSearchReachable.getClient().indices().delete(new DeleteIndexRequest.Builder().index(indexName).build());
            } catch (IOException | RuntimeException ignored) {
                // Best-effort cleanup for integration infrastructure.
            }
        }
    }

    @Test
    void repeatedAuthFailures_disableOpenSearch_and_stopExport_whenNoOtherDestinationRemains() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        ConfigState.State previous = RuntimeConfig.getState();
        String indexName = "af-disable-last-destination-" + Instant.now().toEpochMilli();
        AtomicReference<String> status = new AtomicReference<>();
        try {
            OpenSearchReachable.getClient().indices().create(new CreateIndexRequest.Builder().index(indexName).build());
            ControlStatusBridge.register(status::set);
            IndexingRetryCoordinator.getInstance().clearPendingWork();
            RuntimeConfig.updateState(stateWithDestinations(null, false));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);

            for (int i = 0; i < 3; i++) {
                IndexingRetryCoordinator.getInstance().pushDocument(OpenSearchReachable.BASE_URL, indexName, sampleDoc(i), "exporter");
            }

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.isAnySinkEnabled()).isFalse();
            assertThat(status.get()).contains("OpenSearch export disabled after repeated authentication failures");
            assertThat(status.get()).contains("No destinations remain; export stopped");
        } finally {
            ControlStatusBridge.clear();
            IndexingRetryCoordinator.getInstance().clearPendingWork();
            RuntimeConfig.updateState(previous);
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportStarting(false);
            ExportReporterLifecycle.resetForTests();
            try {
                OpenSearchReachable.getClient().indices().delete(new DeleteIndexRequest.Builder().index(indexName).build());
            } catch (IOException | RuntimeException ignored) {
                // Best-effort cleanup for integration infrastructure.
            }
        }
    }

    private static ConfigState.State stateWithDestinations(Path exportRoot, boolean filesEnabled) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        filesEnabled,
                        exportRoot == null ? "" : exportRoot.toString(),
                        false,
                        filesEnabled,
                        true,
                        ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        true,
                        ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        true,
                        OpenSearchReachable.BASE_URL,
                        "definitely-wrong",
                        "definitely-wrong",
                        false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }

    private static Map<String, Object> sampleDoc(int sequence) {
        return Map.of(
                "meta", Map.of(
                        "schema_version", "1",
                        "indexed_at", Instant.now().toString(),
                        "sequence", sequence),
                "kind", "runtime-test");
    }
}
