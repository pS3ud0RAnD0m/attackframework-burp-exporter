package ai.attackframework.tools.burp.utils.export;

/**
 * Per-bulk OpenSearch outcome classified by index {@code result} when available.
 *
 * <p>{@link #exportedCount()} is {@code created + updated} — documents actually indexed.
 * {@link #successTotal()} also includes {@code noop} operations.</p>
 */
public record BulkOutcomeBreakdown(int created, int updated, int noop, int failed) {

    public BulkOutcomeBreakdown {
        created = Math.max(0, created);
        updated = Math.max(0, updated);
        noop = Math.max(0, noop);
        failed = Math.max(0, failed);
    }

    /** Documents actually indexed to OpenSearch (excludes {@code noop}). */
    public int exportedCount() {
        return created + updated;
    }

    /** All successful bulk item operations. */
    public int successTotal() {
        return created + updated + noop;
    }

    /** Empty breakdown with no successes or failures. */
    public static BulkOutcomeBreakdown empty() {
        return new BulkOutcomeBreakdown(0, 0, 0, 0);
    }

    /**
     * Fallback when the transport layer only knows how many items succeeded without per-item
     * {@code result} classification.
     */
    public static BulkOutcomeBreakdown assumeExported(int successCount) {
        return classified(successCount, successCount);
    }

    /**
     * Fallback when only aggregate success and attempt counts are known (no per-item {@code result}).
     */
    public static BulkOutcomeBreakdown classified(int successCount, int attemptedCount) {
        int failed = Math.max(0, attemptedCount - successCount);
        if (successCount <= 0 && failed <= 0) {
            return empty();
        }
        return new BulkOutcomeBreakdown(0, successCount, 0, failed);
    }

    public BulkOutcomeBreakdown plus(BulkOutcomeBreakdown other) {
        if (other == null) {
            return this;
        }
        return new BulkOutcomeBreakdown(
                created + other.created,
                updated + other.updated,
                noop + other.noop,
                failed + other.failed);
    }
}
