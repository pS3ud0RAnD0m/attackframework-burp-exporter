package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.IndexingRetryCoordinator;

import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.FieldPosition;
import java.text.NumberFormat;
import java.text.ParsePosition;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.LongFunction;
import java.util.function.ToLongFunction;

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

    /** Y-axis tick labels stay at or below this value by rolling KiB → MiB → GiB (or MiB → GiB). */
    static final double AXIS_TICK_LABEL_MAX = 999.0;

    /** Smallest nice axis ceiling ≥ normalized value (1, 1.2, … 10), used for values &gt; 10. */
    private static final double[] NICE_AXIS_NORMALIZED =
            {1.0, 1.2, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0};

    private StatsPanelFormatters() {}

    /**
     * Y-axis label and tick scaling for throughput byte-rate charts (dataset values are KiB/s).
     *
     * @param maxKiBPerSec largest series sample in KiB/s (before headroom)
     * @param headroomMultiplier applied to max when picking the display unit (matches chart range)
     */
    static ChartAxisScale chooseByteRateAxisScale(double maxKiBPerSec, double headroomMultiplier) {
        return chooseAxisScale(
                maxKiBPerSec * headroomMultiplier,
                new String[] { "KiB per second", "MiB per second", "GiB per second" },
                new double[] { 1.0, 1024.0, 1024.0 * 1024.0 });
    }

    /**
     * Y-axis label and tick scaling for the JVM heap chart (dataset values are MiB).
     */
    static ChartAxisScale chooseMemoryAxisScale(double maxMiB, double headroomMultiplier) {
        return chooseAxisScale(
                maxMiB * headroomMultiplier,
                new String[] { "MiB", "GiB" },
                new double[] { 1.0, 1024.0 });
    }

    private static ChartAxisScale chooseAxisScale(
            double rangeUpperInBaseUnits,
            String[] labels,
            double[] divisorsFromBase) {
        for (int unitIndex = 0; unitIndex < labels.length; unitIndex++) {
            double displayUpper = rangeUpperInBaseUnits / divisorsFromBase[unitIndex];
            boolean lastUnit = unitIndex == labels.length - 1;
            if (displayUpper <= AXIS_TICK_LABEL_MAX || lastUnit) {
                return new ChartAxisScale(labels[unitIndex], divisorsFromBase[unitIndex]);
            }
        }
        throw new AssertionError("unreachable");
    }

    /**
     * Range maximum in stored units after headroom and a readable tick ceiling in display units
     * (e.g. raw 3.9 GiB → 4 GiB → {@code 4 * 1024} MiB).
     */
    static double rangeUpperInBaseUnits(double maxInBaseUnits, double headroomMultiplier, ChartAxisScale scale) {
        double rawUpper = maxInBaseUnits * headroomMultiplier;
        double niceDisplayUpper = nicePositiveUpperBound(rawUpper / scale.displayDivisor());
        return niceDisplayUpper * scale.displayDivisor();
    }

    /**
     * Smallest readable axis ceiling ≥ {@code value} ({@code 7.5 → 8}, {@code 750 → 800}, not {@code 1000}).
     */
    static double nicePositiveUpperBound(double value) {
        if (value <= 0.0) {
            return 1.0;
        }
        if (value <= 10.0) {
            return Math.ceil(value);
        }
        double magnitude = Math.pow(10.0, Math.floor(Math.log10(value)));
        double normalized = value / magnitude;
        for (double candidate : NICE_AXIS_NORMALIZED) {
            if (candidate + 1e-9 >= normalized) {
                return candidate * magnitude;
            }
        }
        return 10.0 * magnitude;
    }

    /**
     * Tick step in display units (whole numbers only) targeting about four labels on the axis.
     */
    static int integerDisplayTickStep(double niceDisplayUpper) {
        if (niceDisplayUpper <= 0.0) {
            return 1;
        }
        double step = nicePositiveUpperBound(niceDisplayUpper / 4.0);
        return (int) Math.max(1L, Math.round(step));
    }

    /**
     * Formats range-axis ticks as whole display units ({@code divisor} converts stored values).
     */
    static NumberFormat axisTickNumberFormat(double divisor) {
        DecimalFormat pattern = new DecimalFormat("#,##0", DecimalFormatSymbols.getInstance(Locale.ROOT));
        return new NumberFormat() {
            @Override
            public StringBuffer format(double number, StringBuffer toAppendTo, FieldPosition pos) {
                return pattern.format(Math.round(number / divisor), toAppendTo, pos);
            }

            @Override
            public StringBuffer format(long number, StringBuffer toAppendTo, FieldPosition pos) {
                return format((double) number, toAppendTo, pos);
            }

            @Override
            public Number parse(String source, ParsePosition parsePosition) {
                return null;
            }
        };
    }

    /** Label and divisor from stored units to display units. */
    record ChartAxisScale(String label, double displayDivisor) {}

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
     * Formats spill backlog as {@code "N docs (X.X MiB)"}.
     */
    static String formatSpillQueue(long docs, long bytes) {
        double mib = bytes / (1024.0 * 1024.0);
        return formatWhole(docs) + " docs (" + DECIMAL_ONE.format(mib) + " MiB)";
    }

    /**
     * Summarizes OpenSearch export totals on one line: docs, size, and failure count.
     */
    static String formatExportedSummary(long docs, String sizeHuman, long failures) {
        return formatWhole(docs) + " docs · " + sizeHuman + " · " + formatWhole(failures) + " failures";
    }

    /**
     * Lists per-index retry-queue depths, omitting indexes at zero. Returns {@code "—"} when
     * every queue is empty.
     */
    static String formatRetryQueueDepthSummary() {
        return formatPerIndexNonZero(
                indexKey -> (long) IndexingRetryCoordinator.getInstance()
                        .getQueueSize(RuntimeConfig.indexNameForKey(indexKey)),
                value -> formatWhole(value) + " queued");
    }

    /**
     * Lists per-index oldest queued ages, omitting empty queues. Returns {@code "—"} when none
     * are queued.
     */
    static String formatOldestQueuedAgeSummary() {
        return formatPerIndexNonZero(
                ExportStats::getOldestQueuedAgeMs,
                ageMs -> DECIMAL_ONE.format(ageMs / 1000.0) + "s");
    }

    private static String formatPerIndexNonZero(
            ToLongFunction<String> valueForKey,
            LongFunction<String> formatValue) {
        List<String> sortedKeys = new ArrayList<>(ExportStats.getIndexKeys());
        sortedKeys.sort(String::compareToIgnoreCase);
        List<String> parts = new ArrayList<>();
        for (String indexKey : sortedKeys) {
            long value = valueForKey.applyAsLong(indexKey);
            if (value > 0) {
                parts.add(indexKey + ": " + formatValue.apply(value));
            }
        }
        if (parts.isEmpty()) {
            return "—";
        }
        return String.join(", ", parts);
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

    /**
     * Formats a byte count for a Misc Stats row, choosing KiB / MiB / GiB scale automatically.
     * Returns {@code "-"} for negative inputs so callers can feed "missing" sentinels through
     * without guarding each call site.
     */
    static String formatBytesHuman(long bytes) {
        if (bytes < 0) {
            return "-";
        }
        if (bytes < 1024L) {
            return bytes + " B";
        }
        double kib = bytes / 1024.0;
        if (kib < 1024.0) {
            return DECIMAL_ONE.format(kib) + " KiB";
        }
        double mib = kib / 1024.0;
        if (mib < 1024.0) {
            return DECIMAL_ONE.format(mib) + " MiB";
        }
        double gib = mib / 1024.0;
        return DECIMAL_ONE.format(gib) + " GiB";
    }

}
