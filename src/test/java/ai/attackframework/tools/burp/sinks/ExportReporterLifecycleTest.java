package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.getStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.concurrent.ScheduledExecutorService;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.config.SecureCredentialStore;
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
}
