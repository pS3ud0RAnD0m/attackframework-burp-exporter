package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotPacing;
import ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController;

/**
 * Shared chunk-target tuning for startup snapshot exports.
 */
final class SnapshotBatchTuning {

    private static final int SNAPSHOT_BATCH_INITIAL = 250;
    private static final int SNAPSHOT_BATCH_MIN = 100;
    private static final int SNAPSHOT_BATCH_MAX = 1500;
    private static final long SNAPSHOT_BULK_MAX_BYTES = 5L * 1024 * 1024;
    private static final int LIVE_QUEUE_BACKPRESSURE_DOCS = 10_000;
    private static final int LIVE_SPILL_BACKPRESSURE_DOCS = 2_000;
    private static final long BACKPRESSURE_PAUSE_MS = 75;

    private SnapshotBatchTuning() {}

    /**
     * Shared {@link SnapshotExportEngine.ChunkTargetAdjuster} for snapshot reporters.
     */
    static SnapshotExportEngine.ChunkTargetAdjuster chunkTargetAdjuster() {
        return SnapshotBatchTuning::adjustTargetForChunk;
    }

    /**
     * Returns an initial snapshot chunk target using the shared live-bulk controller as a floor.
     */
    static int initialTarget() {
        int shared = BatchSizeController.getInstance().getCurrentBatchSize();
        int base = Math.max(SNAPSHOT_BATCH_INITIAL, shared);
        return Math.min(SNAPSHOT_BATCH_MAX, Math.max(SNAPSHOT_BATCH_MIN, base));
    }

    /**
     * Adjusts the next chunk target from the previous bulk outcome and observed chunk bytes.
     */
    static int adjustTargetForChunk(int current, int attempted, int succeeded, long chunkBytes) {
        return clampTargetForBulkBytes(adjustTarget(current, attempted, succeeded), chunkBytes, attempted);
    }

    /**
     * Adjusts the next chunk target from the previous bulk outcome.
     */
    static int adjustTarget(int current, int attempted, int succeeded) {
        if (attempted <= 0) {
            return current;
        }
        if (succeeded >= attempted) {
            int grow = Math.max(25, current / 4);
            return Math.min(SNAPSHOT_BATCH_MAX, current + grow);
        }
        int reduced = Math.max(SNAPSHOT_BATCH_MIN, current / 2);
        return Math.min(reduced, Math.max(SNAPSHOT_BATCH_MIN, succeeded));
    }

    /**
     * Caps a doc-count chunk target so projected bulk bytes stay near the snapshot byte ceiling.
     */
    static int clampTargetForBulkBytes(int docTarget, long chunkBytes, int attemptedChunk) {
        if (docTarget <= 0 || attemptedChunk <= 0 || chunkBytes <= 0) {
            return Math.max(SNAPSHOT_BATCH_MIN, docTarget);
        }
        long avgBytes = Math.max(1L, chunkBytes / attemptedChunk);
        int byteCap = (int) Math.min(SNAPSHOT_BATCH_MAX, Math.max(SNAPSHOT_BATCH_MIN, SNAPSHOT_BULK_MAX_BYTES / avgBytes));
        int capped = Math.min(docTarget, byteCap);
        long projected = avgBytes * (long) capped;
        if (projected > SNAPSHOT_BULK_MAX_BYTES) {
            capped = (int) Math.max(SNAPSHOT_BATCH_MIN, SNAPSHOT_BULK_MAX_BYTES / avgBytes);
        }
        return Math.max(SNAPSHOT_BATCH_MIN, capped);
    }

    /**
     * Halves the chunk target when live traffic or JVM GC pressure indicates snapshot contention.
     */
    static int applyLiveBackpressure(int currentTarget) {
        int liveQueueDocs = TrafficExportQueue.getCurrentSize();
        int spillDocs = TrafficExportQueue.getCurrentSpillSize();
        boolean queuePressure = liveQueueDocs >= LIVE_QUEUE_BACKPRESSURE_DOCS
                || spillDocs >= LIVE_SPILL_BACKPRESSURE_DOCS;
        boolean gcPressure = SnapshotPacing.gcSaturated();
        if (!queuePressure && !gcPressure) {
            return currentTarget;
        }
        try {
            Thread.sleep(BACKPRESSURE_PAUSE_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return Math.max(SNAPSHOT_BATCH_MIN, currentTarget / 2);
    }
}
