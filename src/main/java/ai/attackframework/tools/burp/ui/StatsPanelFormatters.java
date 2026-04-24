package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.ExportStats;

import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Pure string formatters for the Misc Stats rows that surface OpenSearch health, retry-queue
 * age, and silent-skip counters. Extracted from {@link StatsPanel} so the logic is
 * unit-testable without a Swing harness.
 *
 * <p>All methods read from {@link ExportStats} (no Swing state) and return plain strings.
 * Returned values are ready to drop into a {@code JLabel}; callers do not need to format
 * further.</p>
 */
final class StatsPanelFormatters {

    private static final DecimalFormat DECIMAL_ONE =
            new DecimalFormat("0.0", DecimalFormatSymbols.getInstance(Locale.ROOT));

    private StatsPanelFormatters() {}

    /**
     * Formats an epoch-ms timestamp as a compact "Xs ago" label.
     *
     * <p>Returns {@code "never"} when the timestamp is non-positive (no success recorded yet),
     * and scales to seconds, minutes, hours, or days as age grows. Used for the OpenSearch
     * connection-health Last Success row.</p>
     */
    static String formatRelativeTime(long epochMs) {
        return formatRelativeTime(epochMs, System.currentTimeMillis());
    }

    /**
     * Testable variant that accepts a caller-supplied "now" so unit tests can exercise each
     * unit boundary (seconds, minutes, hours, days) without relying on real wall-clock time.
     */
    static String formatRelativeTime(long epochMs, long nowMs) {
        if (epochMs <= 0) {
            return "never";
        }
        long delta = nowMs - epochMs;
        if (delta < 0) {
            delta = 0;
        }
        long seconds = delta / 1000L;
        if (seconds < 60) {
            return seconds + "s ago";
        }
        long minutes = seconds / 60L;
        if (minutes < 60) {
            return minutes + "m ago";
        }
        long hours = minutes / 60L;
        if (hours < 24) {
            return hours + "h ago";
        }
        long days = hours / 24L;
        return days + "d ago";
    }

    /**
     * Builds a compact "index=Ns" summary of the oldest-queued-document age per index, suitable
     * for a single Misc Stats row. Indexes with an empty queue are shown as {@code "index=-"}.
     * When {@link ExportStats#getIndexKeys()} is itself empty the method returns a bare
     * {@code "-"} as a defensive fallback.
     */
    static String formatOldestQueuedAges() {
        List<String> sortedKeys = new ArrayList<>(ExportStats.getIndexKeys());
        sortedKeys.sort(String::compareToIgnoreCase);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < sortedKeys.size(); i++) {
            String indexKey = sortedKeys.get(i);
            long ageMs = ExportStats.getOldestQueuedAgeMs(indexKey);
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(indexKey).append('=');
            if (ageMs < 0) {
                sb.append('-');
            } else {
                sb.append(DECIMAL_ONE.format(ageMs / 1000.0)).append('s');
            }
        }
        return sb.length() == 0 ? "-" : sb.toString();
    }

    /**
     * Builds a compact "reason=N" summary from the skip-reason counters, showing {@code "-"}
     * when nothing has been skipped yet. Stable key order is guaranteed by
     * {@link ExportStats#getSkipReasonCounts()}.
     */
    static String formatSkipReasons() {
        Map<String, Long> reasons = ExportStats.getSkipReasonCounts();
        if (reasons.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, Long> entry : reasons.entrySet()) {
            if (!first) {
                sb.append(' ');
            }
            sb.append(entry.getKey()).append('=').append(formatWhole(entry.getValue()));
            first = false;
        }
        return sb.toString();
    }

    private static String formatWhole(long value) {
        return String.format(Locale.ROOT, "%,d", value);
    }
}
