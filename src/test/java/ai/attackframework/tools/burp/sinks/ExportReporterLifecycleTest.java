package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.getStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.config.SecureCredentialStore;
import ai.attackframework.tools.burp.utils.opensearch.IndexingRetryCoordinator;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.Version;
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

            ToolIndexStatsReporter.start();
            SettingsIndexReporter.start();
            FindingsIndexReporter.start();
            SitemapIndexReporter.start();
            ProxyWebSocketIndexReporter.start();

            ExportReporterLifecycle.resetForTests();

            assertThat((ScheduledExecutorService) getStatic(ToolIndexStatsReporter.class, "scheduler")).isNull();
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

            String toolIndexName = IndexNaming.indexNameForShortName("tool");
            IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
            coordinator.pushDocument("https://127.0.0.1:1", toolIndexName, Map.of("message_text", "x"), "tool");
            TrafficExportQueue.offer(Map.of("url", "https://example.com/", "status", 200));

            ExportReporterLifecycle.stopAndClearPendingExportWork();

            long deadline = System.currentTimeMillis() + 2_000;
            while (System.currentTimeMillis() < deadline
                    && (coordinator.getQueueSize(toolIndexName) != 0
                    || TrafficExportQueue.getCurrentSize() != 0
                    || TrafficExportQueue.getCurrentSpillSize() != 0)) {
                LockSupport.parkNanos(50_000_000L);
            }

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(coordinator.getQueueSize(toolIndexName)).isZero();
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isZero();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }
}
