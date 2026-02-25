package ai.attackframework.tools.burp.sinks;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Ensures {@link SettingsIndexReporter} completes without throwing when
 * preconditions are not met (no API, export not running, or Settings not
 * selected). Does not start the scheduler to avoid leaving a daemon thread.
 */
class SettingsIndexReporterTest {

    @AfterEach
    void resetState() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenApiNull() {
        RuntimeConfig.setExportRunning(true);
        MontoyaApiProvider.set(null);
        SettingsIndexReporter.pushSnapshotNow();
        // No exception; may no-op because api is null
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenExportNotRunning() {
        RuntimeConfig.setExportRunning(false);
        SettingsIndexReporter.pushSnapshotNow();
    }

    @Test
    void pushSnapshotIfChanged_completesWithoutThrow_whenApiNull() {
        RuntimeConfig.setExportRunning(true);
        MontoyaApiProvider.set(null);
        SettingsIndexReporter.pushSnapshotIfChanged();
    }

    @Test
    void pushSnapshotIfChanged_completesWithoutThrow_whenExportNotRunning() {
        RuntimeConfig.setExportRunning(false);
        SettingsIndexReporter.pushSnapshotIfChanged();
    }
}
