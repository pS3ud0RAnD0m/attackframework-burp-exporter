package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;

/**
 * Locks exact INFO backlog lines and completion semantics for reporters that export
 * historic backlogs at Start.
 */
class ReporterBacklogLoggingTest {

    private final List<String> infoMessages = new ArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        if ("INFO".equals(level)) {
            infoMessages.add(message);
        }
    };

    @AfterEach
    void tearDown() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        FindingsIndexReporter.stop();
        SitemapIndexReporter.stop();
        ProxyHistoryIndexReporter.stop();
        ProxyWebSocketIndexReporter.stop();
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void findings_pushSnapshotNow_logsBacklogStart_only_noSnapshotComplete() throws Exception {
        Logger.registerListener(listener);
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            SiteMap siteMap = mock(SiteMap.class);
            Scope scope = mock(Scope.class);
            AuditIssue first = mock(AuditIssue.class);
            AuditIssue second = mock(AuditIssue.class);
            when(api.siteMap()).thenReturn(siteMap);
            when(api.scope()).thenReturn(scope);
            when(scope.isInScope(anyString())).thenReturn(true);
            when(siteMap.issues()).thenReturn(List.of(first, second));
            stubMinimalIssue(first, "https://a.example/");
            stubMinimalIssue(second, "https://b.example/");
            MontoyaApiProvider.set(api);

            configureFindingsExport();
            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();

            awaitInfoLine("[Findings] Exporting findings backlog: 2 issue(s).");
            assertThat(infoMessages).noneMatch(line -> line.contains("snapshot complete"));
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void sitemap_pushSnapshotNow_logsBacklogStart_andSnapshotComplete() throws Exception {
        Logger.registerListener(listener);
        try {
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            SiteMap siteMap = mock(SiteMap.class);
            when(api.siteMap()).thenReturn(siteMap);
            when(api.scope().isInScope(anyString())).thenReturn(true);
            HttpRequestResponse item = mock(HttpRequestResponse.class);
            when(siteMap.requestResponses()).thenReturn(List.of(item));
            MontoyaApiProvider.set(api);

            configureSitemapExport();
            SitemapIndexReporter.start();
            SitemapIndexReporter.pushSnapshotNow();

            awaitInfoLine("[Sitemap] Exporting sitemap backlog: 1 item(s).");
            awaitInfoLineStartingWith("[Sitemap] snapshot complete: captured=");
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void proxyWebSocket_pushHistoricSnapshotNow_logsBacklogStart_only_noSnapshotComplete() throws Exception {
        Logger.registerListener(listener);
        try {
            ProxyWebSocketMessage frame = ProxyWebSocketIndexReporterTest.webSocketMessage(1, 1);
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(true);
            when(api.proxy().webSocketHistory()).thenReturn(List.of(frame));
            MontoyaApiProvider.set(api);

            configureProxyWebSocketExport();
            ProxyWebSocketIndexReporter.pushHistoricSnapshotNow();

            awaitInfoLine("[ProxyWebSocket] Exporting proxy WebSocket history backlog: 1 frame(s).");
            assertThat(infoMessages).noneMatch(line -> line.contains("snapshot complete"));
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void proxyHistory_pushSnapshotNow_logsBacklogStart_andSnapshotComplete() throws Exception {
        Logger.registerListener(listener);
        try {
            ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(true);
            when(api.proxy().history()).thenReturn(List.of(item));
            MontoyaApiProvider.set(api);

            configureProxyHistoryExport();
            ProxyHistoryIndexReporter.pushSnapshotNow();

            awaitInfoLine("[ProxyHistory] Exporting proxy history backlog: 1 item(s).");
            awaitInfoLineStartingWith("[ProxyHistory] snapshot complete: captured=");
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    private void awaitInfoLine(String expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (infoMessages.contains(expected)) {
                return;
            }
            Thread.sleep(20);
        }
        assertThat(infoMessages).contains(expected);
    }

    private void awaitInfoLineStartingWith(String prefix) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (infoMessages.stream().anyMatch(line -> line.startsWith(prefix))) {
                return;
            }
            Thread.sleep(20);
        }
        assertThat(infoMessages).anyMatch(line -> line.startsWith(prefix));
    }

    private static void stubMinimalIssue(AuditIssue issue, String baseUrl) {
        when(issue.baseUrl()).thenReturn(baseUrl);
        when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.requestResponses()).thenReturn(List.of());
        when(issue.definition()).thenReturn(null);
    }

    private static void configureFindingsExport() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_FINDINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
    }

    private static void configureSitemapExport() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_SITEMAP),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
    }

    private static void configureProxyWebSocketExport() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy_history"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
    }

    private static void configureProxyHistoryExport() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy_history"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
    }
}
