package ai.attackframework.tools.burp.sinks;

import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.ControlStatusBridge;
import ai.attackframework.tools.burp.utils.DiskSpaceGuard;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.config.SecureCredentialStore;
import ai.attackframework.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Coordinates intentional shutdown and reset of long-lived export reporters.
 *
 * <p>This helper centralizes lifecycle transitions so UI stop actions, test teardown, and other
 * reset paths do not need to duplicate per-reporter cleanup logic. Safe to call multiple times.
 * Not all export paths maintain a scheduler, so this class stops only the reporters that own
 * recurring background work or session-scoped reporter state.</p>
 */
public final class ExportReporterLifecycle {
    private ExportReporterLifecycle() {}

    /**
     * Stops recurring background reporters and clears their in-memory session state.
     *
     * <p>Safe to call from any thread. Callers should set {@link RuntimeConfig#setExportRunning(boolean)}
     * to {@code false} before invoking this method so in-flight work exits cooperatively.</p>
     */
    public static void stopBackgroundReporters() {
        ToolIndexStatsReporter.stop();
        SettingsIndexReporter.stop();
        FindingsIndexReporter.stop();
        SitemapIndexReporter.stop();
        ProxyWebSocketIndexReporter.stop();
    }

    /**
     * Stops recurring reporters and clears queued export work that would otherwise keep retrying.
     *
     * <p>Use when the UI transitions to a stopped state, including failed Start attempts, so the
     * runtime matches what the Start/Stop controls show.</p>
     */
    public static void stopAndClearPendingExportWork() {
        RuntimeConfig.setExportRunning(false);
        stopBackgroundReporters();
        TrafficExportQueue.clearPendingWork();
        IndexingRetryCoordinator.getInstance().clearPendingWork();
        FileExportService.resetForRuntime();
    }

    /**
     * Stops recurring reporters and clears process-local exporter session state.
     *
     * <p>Used by extension unload and test teardown so reloads start from a clean
     * in-memory baseline.</p>
     */
    public static void stopAndClearSessionState() {
        stopAndClearPendingExportWork();
        BurpRuntimeMetadata.clear();
        MontoyaApiProvider.set(null);
        SecureCredentialStore.clearAll();
    }

    /**
     * Resets reporter-related process state for test teardown.
     *
     * <p>In addition to stopping background reporters, this clears session-only credential state,
     * cached Burp metadata, the Montoya API provider, and the export-running flag so subsequent
     * tests start from a clean process-local baseline.</p>
     */
    public static void resetForTests() {
        stopAndClearSessionState();
        ControlStatusBridge.clear();
        DiskSpaceGuard.resetForTests();
        FileExportService.resetForTests();
    }
}
