package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.getStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.config.SecureCredentialStore;
import ai.attackframework.tools.burp.utils.opensearch.IndexingRetryCoordinator;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.project.Project;

class ExportReporterLifecycleTest {

    @Test
    void resetForTests_stopsSchedulers_and_clearsProcessLocalState() {
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            BurpSuite burpSuite = mock(BurpSuite.class);
            Version version = mock(Version.class);
            Project project = mock(Project.class);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(api.project()).thenReturn(project);
            when(burpSuite.version()).thenReturn(version);
            when(project.id()).thenReturn("project-123");

            MontoyaApiProvider.set(api);
            BurpRuntimeMetadata.prime(api);
            RuntimeConfig.setExportRunning(true);
            SecureCredentialStore.saveOpenSearchCredentials("user", "pass");

            ExporterIndexStatsReporter.start();
            SettingsIndexReporter.start();
            FindingsIndexReporter.start();
            SitemapIndexReporter.start();
            ProxyWebSocketIndexReporter.start();

            ExportReporterLifecycle.resetForTests();

            assertThat((ScheduledExecutorService) getStatic(ExporterIndexStatsReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(SettingsIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(FindingsIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(SitemapIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(ProxyWebSocketIndexReporter.class, "scheduler")).isNull();
            assertThat(MontoyaApiProvider.get()).isNull();
            assertThat(BurpRuntimeMetadata.burpVersion()).isNull();
            assertThat(BurpRuntimeMetadata.projectId()).isNull();
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(SecureCredentialStore.loadOpenSearchCredentials().username()).isEmpty();
            assertThat(SecureCredentialStore.loadOpenSearchCredentials().password()).isEmpty();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void stopAndClearPendingExportWork_clearsRetryAndTrafficBacklog() {
        try {
            RuntimeConfig.setExportRunning(true);

            String exporterIndexName = IndexNaming.indexNameForShortName("exporter");
            IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
            coordinator.pushDocument("https://127.0.0.1:1", exporterIndexName, Map.of("message_text", "x"), "exporter");
            TrafficExportQueue.offer(Map.of("url", "https://example.com/", "status", 200));

            ExportReporterLifecycle.stopAndClearPendingExportWork();

            long deadline = System.currentTimeMillis() + 2_000;
            while (System.currentTimeMillis() < deadline
                    && (coordinator.getQueueSize(exporterIndexName) != 0
                    || TrafficExportQueue.getCurrentSize() != 0
                    || TrafficExportQueue.getCurrentSpillSize() != 0)) {
                LockSupport.parkNanos(50_000_000L);
            }

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(coordinator.getQueueSize(exporterIndexName)).isZero();
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void stopAndClearPendingExportWork_clearsRepeaterLiveMetadataTracker() {
        try {
            HttpRequestResponse exchange = requestResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            RepeaterMetadataFields.Metadata metadata =
                    new RepeaterMetadataFields.Metadata("live-tab", "live-group");
            long now = System.currentTimeMillis();

            RepeaterLiveMetadataTracker.observe(exchange, metadata, now);

            assertThat(RepeaterLiveMetadataTracker.resolveRequestResolution(exchange.request(), now).metadata())
                    .isEqualTo(metadata);

            ExportReporterLifecycle.stopAndClearPendingExportWork();

            assertThat(RepeaterLiveMetadataTracker.resolveRequestResolution(exchange.request(), now).metadata())
                    .isEqualTo(RepeaterMetadataFields.Metadata.empty());
            assertThat(RepeaterLiveMetadataTracker.resolveExchangeResolution(
                    exchange.request(),
                    exchange.response(),
                    now).metadata()).isEqualTo(RepeaterMetadataFields.Metadata.empty());
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void stopAndClearPendingExportWork_flushesQueuedTrafficDocsToFiles_beforeClearingBacklog() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("repeater-history-stop-flush");
            RuntimeConfig.updateState(fileExportState(root));
            RuntimeConfig.setExportRunning(true);

            trafficQueue().offer(trafficDocument("https://example.test/repeater/1", "Tab 1"));
            trafficQueue().offer(trafficDocument("https://example.test/repeater/2", "Tab 2"));

            ExportReporterLifecycle.stopAndClearPendingExportWork();

            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("traffic") + ".jsonl");
            assertThat(jsonlPath).exists();
            assertThat(Files.readAllLines(jsonlPath)).hasSize(2);
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    private static HttpRequestResponse requestResponse(String rawRequest, String rawResponse) {
        HttpRequest request = mock(HttpRequest.class);
        ByteArray requestBytes = byteArray(rawRequest);
        when(request.toByteArray()).thenReturn(requestBytes);

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(request);

        HttpResponse response = mock(HttpResponse.class);
        ByteArray responseBytes = byteArray(rawResponse);
        when(response.toByteArray()).thenReturn(responseBytes);
        when(requestResponse.response()).thenReturn(response);
        return requestResponse;
    }

    private static ByteArray byteArray(String value) {
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.getBytes()).thenReturn(value.getBytes(StandardCharsets.UTF_8));
        return bytes;
    }

    private static LinkedBlockingQueue<Map<String, Object>> trafficQueue() {
        return getStatic(TrafficExportQueue.class, "queue");
    }

    private static ConfigState.State fileExportState(Path root) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        true,
                        root.toString(),
                        true,
                        false,
                        true,
                        ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        false,
                        ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false,
                        "",
                        "",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater_history"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }

    private static Map<String, Object> trafficDocument(String url, String repeaterTabName) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        meta.put("indexed_at", "2026-04-19T00:00:00Z");

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("method", "GET");
        request.put("path", "/repeater");

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", 200);

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", url);
        document.put("method", "GET");
        document.put("path", "/repeater");
        document.put("status", 200);
        document.put("tool", "Repeater History");
        document.put("tool_type", "REPEATER_HISTORY");
        document.put("repeater_tab_name", repeaterTabName);
        document.put("repeater_group_name", "Large Set");
        document.put("request", request);
        document.put("response", response);
        document.put("document_meta", meta);
        return document;
    }
}
