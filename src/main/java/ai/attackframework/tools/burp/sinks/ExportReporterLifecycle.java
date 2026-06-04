package ai.attackframework.tools.burp.sinks;

import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.ControlStatusBridge;
import ai.attackframework.tools.burp.utils.DiskSpaceGuard;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.config.SecureCredentialStore;
import ai.attackframework.tools.burp.utils.opensearch.IndexingRetryCoordinator;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Coordinates intentional shutdown and reset of long-lived export reporters.
 *
 * <p>This helper centralizes lifecycle transitions so UI stop actions, test teardown, and other
 * reset paths do not need to duplicate per-reporter cleanup logic. Safe to call multiple times.
 * Not all export paths maintain a scheduler, so this class stops only the reporters that own
 * recurring background work or session-scoped reporter state.</p>
 */
public final class ExportReporterLifecycle {

    /** Max wait for {@link #releaseRunResourcesAsync()} before the Stop UI shows Stopped. */
    public static final long STOP_UI_RECLAIM_TIMEOUT_MS = 10_000L;

    private ExportReporterLifecycle() {}

    /**
     * Holds the most recent {@link #releaseRunResourcesAsync()} worker so test teardown can join
     * it deterministically. Production callers do not need to await; the daemon thread completes
     * on its own. Tests must await before issuing further OpenSearch traffic in the same JVM,
     * because {@link OpenSearchConnector#closeAll()} closes pooled clients that other tests may
     * still hold references to.
     */
    private static final AtomicReference<Thread> lastStopReclaimThread = new AtomicReference<>();

    /**
     * Stops recurring background reporters and clears their in-memory session state.
     *
     * <p>Safe to call from any thread. Callers should set {@link RuntimeConfig#setExportRunning(boolean)}
     * to {@code false} before invoking this method so in-flight work exits cooperatively.</p>
     */
    public static void stopBackgroundReporters() {
        ExporterIndexStatsReporter.stop();
        SettingsIndexReporter.stop();
        FindingsIndexReporter.stop();
        SitemapIndexReporter.stop();
        ProxyWebSocketIndexReporter.stop();
        ProxyHistoryIndexReporter.stop();
        TrafficHttpHandlerSupport.stop();
    }

    /**
     * Clears repeater tab and live-metadata state held for the current export run.
     *
     * <p>Call after {@link TrafficExportQueue#stopWorker()} so in-flight traffic indexing can
     * finish before run-scoped repeater caches are discarded.</p>
     */
    public static void clearRepeaterRunState() {
        RepeaterTabsIndexReporter.clearRunState();
        RepeaterLiveMetadataTracker.clear();
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
        clearRepeaterRunState();
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
        IndexingRetryCoordinator.getInstance().clearPendingWork();
        IndexingRetryCoordinator.getInstance().stopDrainThread();
        FileExportService.resetForRuntime();
    }

    /**
     * Releases run-scoped resources off-thread so the user-Stop click path stays responsive.
     *
     * <p>Closes the cached OpenSearch transport and classic HTTP client pools. Apache HC5 pool
     * shutdown can briefly block while pending connections drain, so the call runs on a
     * short-lived daemon thread rather than the EDT or the start-abort worker.</p>
     *
     * <p>Intentionally NOT invoked from auto-abort paths: a failed Start did not establish a
     * running export, and synchronously closing pools mid-abort can starve the EDT during the
     * abort acknowledgement. The unload path performs the same closure synchronously via
     * {@link ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector#closeAll()}.</p>
     */
    public static void releaseRunResourcesAsync() {
        Thread t = new Thread(
                OpenSearchConnector::closeAll,
                "attackframework-stop-reclaim");
        t.setDaemon(true);
        lastStopReclaimThread.set(t);
        t.start();
    }

    /**
     * Awaits completion of the most recent {@link #releaseRunResourcesAsync()} worker, if any.
     *
     * <p>Intended for test teardown so a Stop-triggered async {@link OpenSearchConnector#closeAll()}
     * cannot race with a subsequent integration test that fetches a cached client. Returns once
     * the thread terminates or the wait expires; thread-interruption is preserved.</p>
     *
     * @param timeoutMillis maximum time to wait, in milliseconds; {@code 0} waits indefinitely
     */
    public static void awaitStopReclaim(long timeoutMillis) {
        Thread t = lastStopReclaimThread.getAndSet(null);
        if (t == null) {
            return;
        }
        try {
            t.join(timeoutMillis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Stops recurring reporters and clears process-local exporter session state.
     *
     * <p>Used by extension unload and test teardown so reloads start from a clean
     * in-memory baseline.</p>
     */
    public static void stopAndClearSessionState() {
        stopAndClearPendingExportWork();
        RepeaterTabsIndexReporter.clearSessionState();
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
        // Wait for any in-flight Stop-triggered async closeAll() worker to finish before clearing
        // session state. Otherwise the daemon can close cached OpenSearch clients while a later
        // test is mid-call, surfacing as "Connection pool shut down" or "Socket closed".
        awaitStopReclaim(5_000L);
        stopAndClearSessionState();
        ControlStatusBridge.clear();
        DiskSpaceGuard.resetForTests();
        ExportStats.resetForTests();
        FileExportService.resetForTests();
    }
}
