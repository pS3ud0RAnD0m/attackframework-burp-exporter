package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Ensures {@link FindingsIndexReporter} completes without throwing when
 * preconditions are not met (no API, export not running, or Findings not
 * selected). Does not start the scheduler to avoid leaving a daemon thread.
 */
class FindingsIndexReporterTest {
    private final ConfigState.State previousState = RuntimeConfig.getState();
    private final MontoyaApi previousApi = MontoyaApiProvider.get();

    private void resetState() {
        FindingsIndexReporter.stop();
        RuntimeConfig.updateState(previousState);
        MontoyaApiProvider.set(previousApi);
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenApiNull() {
        try {
            RuntimeConfig.setExportRunning(true);
            MontoyaApiProvider.set(null);
            FindingsIndexReporter.pushSnapshotNow();
        } finally {
            resetState();
        }
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenExportNotRunning() {
        try {
            RuntimeConfig.setExportRunning(false);
            FindingsIndexReporter.pushSnapshotNow();
        } finally {
            resetState();
        }
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenFindingsNotInDataSources() {
        try {
            ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false);
            ConfigState.State state = new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    sinks,
                    ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null);
            RuntimeConfig.updateState(state);
            RuntimeConfig.setExportRunning(true);
            FindingsIndexReporter.pushSnapshotNow();
        } finally {
            resetState();
        }
    }

    @Test
    void pushNewIssuesOnly_completesWithoutThrow_whenApiNull() {
        try {
            RuntimeConfig.setExportRunning(true);
            MontoyaApiProvider.set(null);
            FindingsIndexReporter.pushNewIssuesOnly();
        } finally {
            resetState();
        }
    }

    @Test
    void pushNewIssuesOnly_completesWithoutThrow_whenExportNotRunning() {
        try {
            RuntimeConfig.setExportRunning(false);
            FindingsIndexReporter.pushNewIssuesOnly();
        } finally {
            resetState();
        }
    }

    @Test
    void pushNewIssuesOnly_completesWithoutThrow_whenFindingsNotInDataSources() {
        try {
            ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false);
            ConfigState.State state = new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    sinks,
                    ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null);
            RuntimeConfig.updateState(state);
            RuntimeConfig.setExportRunning(true);
            FindingsIndexReporter.pushNewIssuesOnly();
        } finally {
            resetState();
        }
    }

    @Test
    void pushNewIssuesOnly_skipsSiteMapIssues_whenCommunityEditionStripsFindingsSource() {
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            BurpSuite burpSuite = mock(BurpSuite.class);
            Version version = mock(Version.class);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(burpSuite.version()).thenReturn(version);
            when(version.edition()).thenReturn(BurpSuiteEdition.COMMUNITY_EDITION);
            MontoyaApiProvider.set(api);

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_FINDINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            RuntimeConfig.setExportRunning(true);

            FindingsIndexReporter.pushNewIssuesOnly();

            assertThat(RuntimeConfig.getState().dataSources()).doesNotContain(ConfigKeys.SRC_FINDINGS);
            verify(api, never()).siteMap();
        } finally {
            resetState();
        }
    }

    @Test
    void buildFindingDoc_survivesMalformedRequestInRequestResponses() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/login");
        when(request.pathWithoutQuery()).thenReturn("/login");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenThrow(new IllegalStateException("malformed"));
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(request);
        when(rr.hasResponse()).thenReturn(false);

        HttpService svc = mock(HttpService.class);
        when(svc.host()).thenReturn("auth.example.com");
        when(svc.port()).thenReturn(443);
        when(svc.secure()).thenReturn(true);

        AuditIssue issue = mock(AuditIssue.class);
        when(issue.name()).thenReturn("Test Issue");
        when(issue.baseUrl()).thenReturn("https://auth.example.com/login");
        when(issue.severity()).thenReturn(AuditIssueSeverity.MEDIUM);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.detail()).thenReturn("details");
        when(issue.remediation()).thenReturn("fix it");
        when(issue.httpService()).thenReturn(svc);
        when(issue.requestResponses()).thenReturn(List.of(rr));
        when(issue.definition()).thenReturn(null);

        Map<?, ?> doc = (Map<?, ?>) callStatic(FindingsIndexReporter.class, "buildFindingDoc", issue);

        assertThat(doc).isNotNull();
        assertThat(doc.get("name")).isEqualTo("Test Issue");
        assertThat(doc.get("url")).isEqualTo("https://auth.example.com/login");
        assertThat(doc.get("severity")).isEqualTo("MEDIUM");
        assertThat(doc.get("request_responses_missing")).isEqualTo(false);
        assertThat(doc.get("request_responses"))
                .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class))
                .hasSize(1);
    }

    @Test
    void pushSnapshotNow_skipsSiteMap_whenCommunityEditionStripsFindingsSource() {
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            BurpSuite burpSuite = mock(BurpSuite.class);
            Version version = mock(Version.class);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(burpSuite.version()).thenReturn(version);
            when(version.edition()).thenReturn(BurpSuiteEdition.COMMUNITY_EDITION);
            MontoyaApiProvider.set(api);

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_FINDINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            RuntimeConfig.setExportRunning(true);

            FindingsIndexReporter.pushSnapshotNow();

            assertThat(RuntimeConfig.getState().dataSources()).doesNotContain(ConfigKeys.SRC_FINDINGS);
            verify(api, never()).siteMap();
        } finally {
            resetState();
        }
    }
}
