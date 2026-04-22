package ai.attackframework.tools.burp.sinks;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;

/**
 * Shared bulk-outcome accounting for OpenSearch bulk requests across reporters.
 *
 * <p>Centralizes the success/failure bookkeeping that one-shot and periodic reporters
 * (Sitemap, Findings, and — via {@link TrafficRouteBucket#recordBulkOutcome} — the traffic
 * reporters) would otherwise duplicate. Callers invoke this helper once per bulk request.</p>
 *
 * <p>Side effects when {@code openSearchActive} is {@code true}:
 * <ul>
 *   <li>Increments {@link ExportStats#recordSuccess(String, int)} by the clamped successful
 *       document count;</li>
 *   <li>Increments {@link ExportStats#recordFailure(String, int)} by {@code attempted - sent}
 *       when positive;</li>
 *   <li>On failure, sets {@link ExportStats#recordLastError(String, String)} and emits a
 *       panel-only warn line in the format
 *       {@code [logPrefix] label completed with N failure(s).}.</li>
 * </ul>
 *
 * <p>Counts are clamped so {@code sent} is bounded to {@code [0, max(0, attempted)]}; this makes
 * the helper self-defending against caller bugs that report more successes than attempts.</p>
 *
 * <p>When {@code openSearchActive} is {@code false}, the helper returns the clamped success count
 * but updates no counters (file-sink accounting is handled elsewhere).</p>
 */
public final class BulkOutcomeRecorder {

    private BulkOutcomeRecorder() {}

    /**
     * Records the outcome of one bulk request for {@code indexKey}.
     *
     * @param indexKey logical index key (for example {@code "traffic"}, {@code "sitemap"},
     *                 {@code "findings"}); must not be {@code null} or blank
     * @param logPrefix short bracket prefix used in panel log lines (for example
     *                  {@code "Traffic"}, {@code "Sitemap"}); falls back to {@code "Export"}
     *                  when blank or {@code null}
     * @param label human-readable label describing what the bulk represents (for example
     *              {@code "Bulk push"}, {@code "Proxy history chunk"}); falls back to
     *              {@code "Bulk"} when blank or {@code null}
     * @param attempted number of documents submitted in the bulk; negative values are clamped to 0
     * @param sent number of documents acknowledged successful; clamped to
     *             {@code [0, max(0, attempted)]}
     * @param openSearchActive whether the OpenSearch sink was active for this bulk
     * @return the clamped success count (useful when callers need to decide whether the batch
     *         was fully pushed)
     * @throws IllegalArgumentException if {@code indexKey} is {@code null} or blank
     */
    public static int record(
            String indexKey,
            String logPrefix,
            String label,
            int attempted,
            int sent,
            boolean openSearchActive) {
        if (indexKey == null || indexKey.isBlank()) {
            throw new IllegalArgumentException("indexKey must not be blank");
        }
        int clampedAttempted = Math.max(0, attempted);
        int clampedSent = Math.max(0, Math.min(sent, clampedAttempted));
        if (!openSearchActive) {
            return clampedSent;
        }
        if (clampedSent > 0) {
            ExportStats.recordSuccess(indexKey, clampedSent);
        }
        int failure = clampedAttempted - clampedSent;
        if (failure > 0) {
            ExportStats.recordFailure(indexKey, failure);
            String resolvedLabel = (label == null || label.isBlank()) ? "Bulk" : label.trim();
            String resolvedPrefix = (logPrefix == null || logPrefix.isBlank()) ? "Export" : logPrefix.trim();
            ExportStats.recordLastError(indexKey, resolvedLabel + " had " + failure + " failure(s)");
            Logger.logWarnPanelOnly("[" + resolvedPrefix + "] " + resolvedLabel
                    + " completed with " + failure + " failure(s).");
        }
        return clampedSent;
    }
}
