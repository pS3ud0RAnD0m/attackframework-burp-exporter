package ai.attackframework.tools.burp.sinks;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Ensures {@link FindingsIndexReporter} completes without throwing when
 * preconditions are not met (no API, export not running, or Findings not
 * selected). Does not start the scheduler to avoid leaving a daemon thread.
 */
class FindingsIndexReporterTest {

    @AfterEach
    void resetState() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenApiNull() {
        RuntimeConfig.setExportRunning(true);
        MontoyaApiProvider.set(null);
        FindingsIndexReporter.pushSnapshotNow();
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenExportNotRunning() {
        RuntimeConfig.setExportRunning(false);
        FindingsIndexReporter.pushSnapshotNow();
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenFindingsNotInDataSources() {
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, "http://opensearch.url:9200");
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks);
        RuntimeConfig.updateState(state);
        RuntimeConfig.setExportRunning(true);
        FindingsIndexReporter.pushSnapshotNow();
    }

    @Test
    void pushNewIssuesOnly_completesWithoutThrow_whenApiNull() {
        RuntimeConfig.setExportRunning(true);
        MontoyaApiProvider.set(null);
        FindingsIndexReporter.pushNewIssuesOnly();
    }

    @Test
    void pushNewIssuesOnly_completesWithoutThrow_whenExportNotRunning() {
        RuntimeConfig.setExportRunning(false);
        FindingsIndexReporter.pushNewIssuesOnly();
    }

    @Test
    void pushNewIssuesOnly_completesWithoutThrow_whenFindingsNotInDataSources() {
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, "http://opensearch.url:9200");
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks);
        RuntimeConfig.updateState(state);
        RuntimeConfig.setExportRunning(true);
        FindingsIndexReporter.pushNewIssuesOnly();
    }
}
