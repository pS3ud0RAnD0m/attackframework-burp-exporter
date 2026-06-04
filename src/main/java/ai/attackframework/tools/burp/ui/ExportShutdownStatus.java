package ai.attackframework.tools.burp.ui;

import java.util.List;
import java.util.Locale;

import ai.attackframework.tools.burp.sinks.TrafficExportQueue;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * User-visible control-status text for cooperative export shutdown.
 *
 * <p>Messages reflect actual behavior: the traffic drain worker finishes the in-flight bulk
 * batch before exit, then queued traffic and retries are cleared (not drained).</p>
 */
public final class ExportShutdownStatus {

    private static final String PREFIX = "Stopping: ";

    private ExportShutdownStatus() {}

    /**
     * Point-in-time queue depths captured on the EDT when the user clicks Stop.
     *
     * @param trafficQueued in-memory traffic queue size
     * @param spillQueued spill file queue size
     * @param retryQueued total documents across per-index retry queues
     * @param batchSize current traffic bulk batch size cap
     */
    public record Snapshot(int trafficQueued, int spillQueued, int retryQueued, int batchSize) {

        public int totalBacklog() {
            return Math.max(0, trafficQueued) + Math.max(0, spillQueued) + Math.max(0, retryQueued);
        }
    }

    /** Captures queue depths and batch size for stop status messaging. Caller must invoke on the EDT. */
    public static Snapshot capture() {
        int trafficQueued = TrafficExportQueue.getCurrentSize();
        int spillQueued = TrafficExportQueue.getCurrentSpillSize();
        int retryQueued = totalRetryQueueDepth();
        int batchSize = BatchSizeController.getInstance().getCurrentBatchSize();
        return new Snapshot(trafficQueued, spillQueued, retryQueued, batchSize);
    }

    /** Initial status line shown immediately when Stop is clicked. */
    public static String initialStoppingMessage(Snapshot snapshot) {
        StringBuilder detail = new StringBuilder("waiting for in-flight traffic batch");
        int backlog = snapshot.totalBacklog();
        if (backlog > 0) {
            detail.append(", then clearing ").append(formatWhole(backlog)).append(" queued docs");
        }
        return PREFIX + detail + " …";
    }

    /** Status while the traffic drain worker is shutting down (in-flight bulk may still complete). */
    public static String waitingForBatchMessage() {
        return PREFIX + "waiting for in-flight traffic batch …";
    }

    /** Status while memory/spill/retry queues are cleared after the worker stops. */
    public static String clearingQueuedTrafficMessage(Snapshot snapshot) {
        int backlog = snapshot.totalBacklog();
        if (backlog > 0) {
            return PREFIX + "clearing " + formatWhole(backlog) + " queued docs …";
        }
        return PREFIX + "clearing queued traffic …";
    }

    /** Status while OpenSearch client pools are closed. */
    public static String closingConnectionsMessage() {
        return PREFIX + "closing OpenSearch connections …";
    }

    /** Final status when shutdown is complete. */
    public static String stoppedMessage() {
        return "Stopped";
    }

    private static int totalRetryQueueDepth() {
        IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
        int total = 0;
        List<String> keys = ExportStats.getIndexKeys();
        for (String indexKey : keys) {
            String indexName = RuntimeConfig.indexNameForKey(indexKey);
            total += coordinator.getQueueSize(indexName);
        }
        return total;
    }

    private static String formatWhole(int value) {
        return String.format(Locale.ROOT, "%,d", value);
    }
}
