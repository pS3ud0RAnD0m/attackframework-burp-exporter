package ai.attackframework.tools.burp.sinks;

import java.util.List;

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
