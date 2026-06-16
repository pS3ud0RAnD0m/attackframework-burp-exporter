package ai.attackframework.tools.burp.utils.export;

/**
 * Outcome of one prepared bulk push through {@code OpenSearchClientWrapper}.
 *
 * @param attempted documents offered to sinks
 * @param exportedCount OpenSearch docs actually indexed ({@code created + updated})
 * @param breakdown per-item OpenSearch classification when the sink was active
 */
public record BulkPushOutcome(
        int attempted,
        int exportedCount,
        BulkOutcomeBreakdown breakdown,
        long fileFlushMs,
        long openSearchFlushMs) {

    public BulkPushOutcome(int attempted, int exportedCount, BulkOutcomeBreakdown breakdown) {
        this(attempted, exportedCount, breakdown, -1L, -1L);
    }

    /**
     * Documents delivered to sinks for this chunk (always all attempted documents when sinks run).
     */
    public int accepted() {
        return attempted;
    }

    /**
     * OpenSearch-indexed document count ({@code created + updated}); excludes {@code noop} items.
     */
    public int successCount() {
        return exportedCount;
    }

    public static BulkPushOutcome fileOnly(int attempted, long fileFlushMs) {
        return new BulkPushOutcome(attempted, attempted, BulkOutcomeBreakdown.empty(), fileFlushMs, -1L);
    }

    public static BulkPushOutcome fileOnly(int attempted) {
        return fileOnly(attempted, -1L);
    }

    public static BulkPushOutcome empty() {
        return new BulkPushOutcome(0, 0, BulkOutcomeBreakdown.empty());
    }

}
