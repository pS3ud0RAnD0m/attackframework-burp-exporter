package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchPushCancellation;

/**
 * Shared bulk-outcome accounting for OpenSearch bulk requests across reporters.
 *
 * <p>Centralizes the success/failure bookkeeping that one-shot and periodic reporters
 * (Sitemap, Findings, and — via {@link TrafficRouteBucket#recordBulkOutcome} — the traffic
 * reporters) would otherwise duplicate. Callers invoke this helper once per bulk request.</p>
 */
public final class BulkOutcomeRecorder {

    private BulkOutcomeRecorder() {}

    /**
     * Records one bulk outcome from {@link ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper#pushPreparedBulk}.
     */
    public static int record(
            String indexKey,
            String logPrefix,
            String label,
            BulkPushOutcome outcome,
            boolean openSearchActive) {
        if (outcome == null) {
            return record(indexKey, logPrefix, label, 0, 0, openSearchActive, null);
        }
        return record(
                indexKey,
                logPrefix,
                label,
                outcome.attempted(),
                outcome.successCount(),
                openSearchActive,
                outcome.breakdown());
    }

    public static int record(
            String indexKey,
            String logPrefix,
            String label,
            int attempted,
            int sent,
            boolean openSearchActive) {
        return record(indexKey, logPrefix, label, attempted, sent, openSearchActive, null);
    }

    public static int record(
            String indexKey,
            String logPrefix,
            String label,
            int attempted,
            int sent,
            boolean openSearchActive,
            BulkOutcomeBreakdown breakdown) {
        if (indexKey == null || indexKey.isBlank()) {
            throw new IllegalArgumentException("indexKey must not be blank");
        }
        int clampedAttempted = Math.max(0, attempted);
        int clampedSent = Math.max(0, Math.min(sent, clampedAttempted));
        if (!openSearchActive) {
            return clampedSent;
        }
        if (breakdown != null) {
            ExportStats.recordBulkBreakdown(indexKey, breakdown);
        } else if (clampedSent > 0) {
            ExportStats.recordSuccess(indexKey, clampedSent);
        }
        int transportFailure = clampedAttempted - clampedSent;
        int failure = breakdown != null
                ? Math.max(breakdown.failed(), transportFailure)
                : transportFailure;
        if (failure > 0) {
            if (OpenSearchPushCancellation.shouldSuppressFailureAccounting()) {
                return clampedSent;
            }
            if (breakdown == null) {
                ExportStats.recordFailure(indexKey, failure);
            } else if (breakdown.failed() < failure) {
                ExportStats.recordFailure(indexKey, failure - breakdown.failed());
            }
            String resolvedLabel = (label == null || label.isBlank()) ? "bulk push" : label.trim();
            String resolvedSource = (logPrefix == null || logPrefix.isBlank()) ? "Export" : logPrefix.trim();
            ExportStats.recordLastError(indexKey, resolvedLabel + " had " + failure + " failure(s)");
            Logger.logWarnPanelOnly("[OpenSearch] " + resolvedSource + ": " + lowerFirst(resolvedLabel)
                    + " completed with " + failure + " failure(s).");
        }
        return clampedSent;
    }

    private static String lowerFirst(String value) {
        if (value == null || value.isBlank()) {
            return "bulk";
        }
        return Character.toLowerCase(value.charAt(0)) + value.substring(1);
    }
}
