package ai.attackframework.tools.burp;

import static ai.attackframework.tools.burp.testutils.Reflect.getStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.awt.Component;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.sinks.FindingsIndexReporter;
import ai.attackframework.tools.burp.sinks.ProxyWebSocketIndexReporter;
import ai.attackframework.tools.burp.sinks.SettingsIndexReporter;
import ai.attackframework.tools.burp.sinks.SitemapIndexReporter;
import ai.attackframework.tools.burp.sinks.ToolIndexStatsReporter;
import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.Version;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.project.Project;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.core.BurpSuiteEdition;

class ExporterLifecycleTest {

    @Test
    void initialize_registersUnloadHook_and_leavesRecurringReportersStopped_untilStart() {
        try {
            ApiFixture fixture = new ApiFixture();

            new Exporter().initialize(fixture.api);

            assertThat(fixture.unloadHandler.get()).isNotNull();
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(MontoyaApiProvider.get()).isSameAs(fixture.api);
            assertThat((ScheduledExecutorService) getStatic(ToolIndexStatsReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(SettingsIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(FindingsIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(SitemapIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(ProxyWebSocketIndexReporter.class, "scheduler")).isNull();

            verify(fixture.extension).setName("Attack Framework: Burp Exporter");
            verify(fixture.extension).registerUnloadingHandler(any(ExtensionUnloadingHandler.class));
            verify(fixture.userInterface).registerSuiteTab(eq("Attack Framework"), any(Component.class));
            verify(fixture.http).registerHttpHandler(any());
        } finally {
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void unloadingHandler_deregistersResources_and_stopsBackgroundWork() {
        try {
            ApiFixture fixture = new ApiFixture();
            new Exporter().initialize(fixture.api);

            RuntimeConfig.setExportRunning(true);
            ToolIndexStatsReporter.start();
            SettingsIndexReporter.start();
            FindingsIndexReporter.start();
            SitemapIndexReporter.start();
            ProxyWebSocketIndexReporter.start();

            fixture.unloadHandler.get().extensionUnloaded();

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(MontoyaApiProvider.get()).isNull();
            assertThat(BurpRuntimeMetadata.burpVersion()).isNull();
            assertThat(BurpRuntimeMetadata.projectId()).isNull();
            assertThat((ScheduledExecutorService) getStatic(ToolIndexStatsReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(SettingsIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(FindingsIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(SitemapIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(ProxyWebSocketIndexReporter.class, "scheduler")).isNull();
            assertThat((List<?>) getStatic(Logger.class, "LISTENERS")).isEmpty();

            verify(fixture.httpRegistration).deregister();
            verify(fixture.suiteTabRegistration).deregister();
            verify(fixture.unloadRegistration, atLeastOnce()).deregister();
        } finally {
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void unloadingHandler_isSafeToInvokeMoreThanOnce() {
        try {
            ApiFixture fixture = new ApiFixture();
            new Exporter().initialize(fixture.api);

            assertThatCode(() -> {
                fixture.unloadHandler.get().extensionUnloaded();
                fixture.unloadHandler.get().extensionUnloaded();
            }).doesNotThrowAnyException();

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(MontoyaApiProvider.get()).isNull();
            assertThat(BurpRuntimeMetadata.burpVersion()).isNull();
            assertThat(BurpRuntimeMetadata.projectId()).isNull();
            assertThat((ScheduledExecutorService) getStatic(ToolIndexStatsReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(SettingsIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(FindingsIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(SitemapIndexReporter.class, "scheduler")).isNull();
            assertThat((ScheduledExecutorService) getStatic(ProxyWebSocketIndexReporter.class, "scheduler")).isNull();
        } finally {
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    private static final class ApiFixture {
        final MontoyaApi api = mock(MontoyaApi.class);
        final Extension extension = mock(Extension.class);
        final UserInterface userInterface = mock(UserInterface.class);
        final Http http = mock(Http.class);
        final Logging logging = mock(Logging.class);
        final BurpSuite burpSuite = mock(BurpSuite.class);
        final Version version = mock(Version.class);
        final Project project = mock(Project.class);
        final Registration unloadRegistration = mock(Registration.class);
        final Registration suiteTabRegistration = mock(Registration.class);
        final Registration httpRegistration = mock(Registration.class);
        final AtomicReference<ExtensionUnloadingHandler> unloadHandler = new AtomicReference<>();

        ApiFixture() {
            when(api.extension()).thenReturn(extension);
            when(api.userInterface()).thenReturn(userInterface);
            when(api.http()).thenReturn(http);
            when(api.logging()).thenReturn(logging);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(api.project()).thenReturn(project);
            when(burpSuite.version()).thenReturn(version);
            when(version.edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL);
            when(project.id()).thenReturn("project-123");
            when(extension.registerUnloadingHandler(any())).thenAnswer(invocation -> {
                unloadHandler.set(invocation.getArgument(0));
                return unloadRegistration;
            });
            when(userInterface.registerSuiteTab(eq("Attack Framework"), any(Component.class)))
                    .thenReturn(suiteTabRegistration);
            when(http.registerHttpHandler(any())).thenReturn(httpRegistration);
        }
    }
}
