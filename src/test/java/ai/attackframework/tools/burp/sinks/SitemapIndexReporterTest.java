package ai.attackframework.tools.burp.sinks;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Ensures {@link SitemapIndexReporter} completes without throwing when
 * preconditions are not met (no API, export not running, or Sitemap not
 * selected). Does not start the scheduler to avoid leaving a daemon thread.
 */
class SitemapIndexReporterTest {

    @AfterEach
    void resetState() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenApiNull() {
        RuntimeConfig.setExportRunning(true);
        MontoyaApiProvider.set(null);
        SitemapIndexReporter.pushSnapshotNow();
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenExportNotRunning() {
        RuntimeConfig.setExportRunning(false);
        SitemapIndexReporter.pushSnapshotNow();
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenSitemapNotInDataSources() {
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, "http://opensearch.url:9200");
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks,
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES);
        RuntimeConfig.updateState(state);
        RuntimeConfig.setExportRunning(true);
        SitemapIndexReporter.pushSnapshotNow();
    }

    @Test
    void pushNewItemsOnly_completesWithoutThrow_whenApiNull() {
        RuntimeConfig.setExportRunning(true);
        MontoyaApiProvider.set(null);
        SitemapIndexReporter.pushNewItemsOnly();
    }

    @Test
    void pushNewItemsOnly_completesWithoutThrow_whenExportNotRunning() {
        RuntimeConfig.setExportRunning(false);
        SitemapIndexReporter.pushNewItemsOnly();
    }

    @Test
    void pushNewItemsOnly_completesWithoutThrow_whenSitemapNotInDataSources() {
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, "http://opensearch.url:9200");
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks,
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES);
        RuntimeConfig.updateState(state);
        RuntimeConfig.setExportRunning(true);
        SitemapIndexReporter.pushNewItemsOnly();
    }
}
