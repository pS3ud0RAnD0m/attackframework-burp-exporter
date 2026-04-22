package ai.attackframework.tools.burp.sinks;

import java.util.function.LongSupplier;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.FileExportStats;
import ai.attackframework.tools.burp.utils.Logger;

/**
 * Shared helper for logging completion summaries of one-shot export waves.
 *
 * <p>Reporters such as {@code ProxyHistoryIndexReporter} and {@code SitemapIndexReporter} run
 * bounded, single-pass exports at Start. This helper captures counter deltas across the run
 * and emits a single {@code INFO}-level panel line with attempted, file, and OpenSearch
 * outcomes. The {@code file={...}; openSearch={...}} body shares the substructure with the
 * Repeater History startup completion summary so operators can visually align per-source
 * totals across reporters; the surrounding prefix and suffix differ per reporter.</p>
 *
 * <p>Two counter sources are supported via {@link #forRoute(TrafficRouteBucket.Route)} and
 * {@link #forIndexKey(String)}: traffic reporters use the per-route bucket counters, while
 * non-traffic reporters (Sitemap, Findings, etc.) use the index-key totals exposed by
 * {@link ExportStats} / {@link FileExportStats}. Both flavors share identical body output.</p>
 */
public final class SnapshotSummary {

    private SnapshotSummary() {}

    /**
     * Snapshots the current file and OpenSearch counters for a traffic route. Use before starting
     * a run and pair with {@link #logInfo} after the run to compute deltas.
     *
     * @param route route whose counters should be tracked; {@code null} returns an empty snapshot
     * @return baseline snapshot; never {@code null}
     */
    public static Baseline forRoute(TrafficRouteBucket.Route route) {
        if (route == null) {
            return Baseline.empty();
        }
        return new Baseline(
                () -> TrafficRouteBucket.fileSuccessCount(route),
                () -> TrafficRouteBucket.fileFailureCount(route),
                () -> TrafficRouteBucket.openSearchSuccessCount(route),
                () -> TrafficRouteBucket.openSearchFailureCount(route),
                TrafficRouteBucket.fileSuccessCount(route),
                TrafficRouteBucket.fileFailureCount(route),
                TrafficRouteBucket.openSearchSuccessCount(route),
                TrafficRouteBucket.openSearchFailureCount(route));
    }

    /**
     * Snapshots the current file and OpenSearch counters for a non-traffic {@code indexKey}.
     *
     * @param indexKey logical index key (for example {@code "sitemap"}, {@code "findings"});
     *                 {@code null} or blank returns an empty snapshot
     * @return baseline snapshot; never {@code null}
     */
    public static Baseline forIndexKey(String indexKey) {
        if (indexKey == null || indexKey.isBlank()) {
            return Baseline.empty();
        }
        String key = indexKey.trim();
        return new Baseline(
                () -> FileExportStats.getSuccessCount(key),
                () -> FileExportStats.getFailureCount(key),
                () -> ExportStats.getSuccessCount(key),
                () -> ExportStats.getFailureCount(key),
                FileExportStats.getSuccessCount(key),
                FileExportStats.getFailureCount(key),
                ExportStats.getSuccessCount(key),
                ExportStats.getFailureCount(key));
    }

    /**
     * Logs a completion summary comparing current counters to {@code baseline}.
     *
     * @param prefix logger bracket prefix (for example {@code "ProxyHistory"}, {@code "Sitemap"})
     * @param baseline snapshot captured before the run started
     * @param attempted total documents attempted in the run (including those that produced no doc)
     * @param durationMs wall-clock run duration in milliseconds
     * @param openSearchActive whether the OpenSearch sink was active for the run
     * @param fileActive whether any file sink was active for the run
     */
    public static void logInfo(
            String prefix,
            Baseline baseline,
            int attempted,
            long durationMs,
            boolean openSearchActive,
            boolean fileActive) {
        Logger.logInfoPanelOnly(formatSummary(prefix, baseline, attempted, durationMs, openSearchActive, fileActive));
    }

    /**
     * Builds the completion-summary line that {@link #logInfo} emits.
     *
     * <p>Package-private so tests can assert the exact format without intercepting the logger.</p>
     */
    static String formatSummary(
            String prefix,
            Baseline baseline,
            int attempted,
            long durationMs,
            boolean openSearchActive,
            boolean fileActive) {
        String label = (prefix == null || prefix.isBlank()) ? "Export" : prefix.trim();
        StringBuilder sb = new StringBuilder(128);
        sb.append('[').append(label).append("] snapshot complete: captured=")
                .append(Math.max(0, attempted));
        String body = formatCompletionBody(baseline, openSearchActive, fileActive);
        if (!body.isEmpty()) {
            sb.append("; ").append(body);
        }
        sb.append(" in ").append(Math.max(0L, durationMs)).append("ms.");
        return sb.toString();
    }

    /**
     * Builds the {@code file={...}; openSearch={...}} body fragment that reporters can compose
     * into their own completion log lines.
     *
     * <p>Each section is included only when the corresponding sink was active for the run. When
     * both are inactive the method returns an empty string. Reporters are responsible for
     * prepending/appending any surrounding prefix, suffix, or separators.</p>
     *
     * @param baseline snapshot captured before the run; {@code null} yields zeroed deltas
     * @param openSearchActive whether the OpenSearch sink was active for the run
     * @param fileActive whether any file sink was active for the run
     * @return fragment such as {@code "file={success=2, failure=0}; openSearch={success=2, failure=0}"};
     *         never {@code null}
     */
    public static String formatCompletionBody(
            Baseline baseline,
            boolean openSearchActive,
            boolean fileActive) {
        long fileSuccessDelta = 0;
        long fileFailureDelta = 0;
        long openSearchSuccessDelta = 0;
        long openSearchFailureDelta = 0;
        if (baseline != null && baseline.hasSource()) {
            fileSuccessDelta = Math.max(0, baseline.fileSuccessNow.getAsLong() - baseline.fileSuccessBefore);
            fileFailureDelta = Math.max(0, baseline.fileFailureNow.getAsLong() - baseline.fileFailureBefore);
            openSearchSuccessDelta = Math.max(0,
                    baseline.openSearchSuccessNow.getAsLong() - baseline.openSearchSuccessBefore);
            openSearchFailureDelta = Math.max(0,
                    baseline.openSearchFailureNow.getAsLong() - baseline.openSearchFailureBefore);
        }
        StringBuilder sb = new StringBuilder(64);
        if (fileActive) {
            sb.append("file={success=").append(fileSuccessDelta)
                    .append(", failure=").append(fileFailureDelta).append('}');
        }
        if (openSearchActive) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append("openSearch={success=").append(openSearchSuccessDelta)
                    .append(", failure=").append(openSearchFailureDelta).append('}');
        }
        return sb.toString();
    }

    /** Baseline counters for a counter source captured before a one-shot run. */
    public static final class Baseline {

        private final LongSupplier fileSuccessNow;
        private final LongSupplier fileFailureNow;
        private final LongSupplier openSearchSuccessNow;
        private final LongSupplier openSearchFailureNow;
        private final long fileSuccessBefore;
        private final long fileFailureBefore;
        private final long openSearchSuccessBefore;
        private final long openSearchFailureBefore;

        private Baseline(
                LongSupplier fileSuccessNow,
                LongSupplier fileFailureNow,
                LongSupplier openSearchSuccessNow,
                LongSupplier openSearchFailureNow,
                long fileSuccessBefore,
                long fileFailureBefore,
                long openSearchSuccessBefore,
                long openSearchFailureBefore) {
            this.fileSuccessNow = fileSuccessNow;
            this.fileFailureNow = fileFailureNow;
            this.openSearchSuccessNow = openSearchSuccessNow;
            this.openSearchFailureNow = openSearchFailureNow;
            this.fileSuccessBefore = fileSuccessBefore;
            this.fileFailureBefore = fileFailureBefore;
            this.openSearchSuccessBefore = openSearchSuccessBefore;
            this.openSearchFailureBefore = openSearchFailureBefore;
        }

        private static Baseline empty() {
            return new Baseline(null, null, null, null, 0, 0, 0, 0);
        }

        private boolean hasSource() {
            return fileSuccessNow != null
                    && fileFailureNow != null
                    && openSearchSuccessNow != null
                    && openSearchFailureNow != null;
        }
    }
}
