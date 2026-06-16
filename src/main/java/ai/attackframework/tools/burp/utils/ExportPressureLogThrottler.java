package ai.attackframework.tools.burp.utils;

import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Aggregates high-volume export pressure events into throttled operator log summaries.
 *
 * <p>Overflow and drop paths can be hit once per document during outages or disk pressure. This
 * helper emits the first event immediately and then only emits a cumulative summary after the
 * configured interval has elapsed. Callers keep their per-event counters in {@link ExportStats};
 * this class is only for bounded human-readable logging. Thread-safe.</p>
 */
public final class ExportPressureLogThrottler {

    /** Default interval between repeated pressure summaries. */
    public static final long DEFAULT_INTERVAL_MS = 30_000L;

    private final String component;
    private final long intervalMs;
    private final LongSupplier clockMs;
    private final Consumer<String> logSink;
    private final ConcurrentHashMap<String, LongAdder> totals = new ConcurrentHashMap<>();
    private final AtomicBoolean firstEmissionDone = new AtomicBoolean();
    private final AtomicLong lastEmissionMs = new AtomicLong(Long.MIN_VALUE);

    /**
     * Creates a throttler that writes warning-level panel logs using the system clock.
     *
     * @param component stable component label used in the log prefix
     */
    public ExportPressureLogThrottler(String component) {
        this(component, DEFAULT_INTERVAL_MS, System::currentTimeMillis, Logger::logWarnPanelOnly);
    }

    /**
     * Creates a throttler with explicit timing and sink dependencies.
     *
     * <p>This constructor is intended for tests and for call sites that need a different log sink.
     * The {@code logSink} must be non-blocking; it may be called from hot export paths.</p>
     *
     * @param component stable component label used in the log prefix
     * @param intervalMs minimum time between repeated summaries after the first emission
     * @param clockMs clock returning wall time in milliseconds
     * @param logSink destination for formatted summary lines
     */
    public ExportPressureLogThrottler(
            String component,
            long intervalMs,
            LongSupplier clockMs,
            Consumer<String> logSink) {
        this.component = component == null || component.isBlank() ? "Export" : component.trim();
        this.intervalMs = Math.max(1L, intervalMs);
        this.clockMs = clockMs == null ? System::currentTimeMillis : clockMs;
        this.logSink = logSink == null ? Logger::logWarnPanelOnly : logSink;
    }

    /**
     * Records one or more pressure events and emits a summary when the throttle allows it.
     *
     * @param reason stable reason key such as {@code spill_queued} or {@code retry_queue_full}
     * @param count number of events to add; ignored when not positive
     * @param contextSupplier optional context appended to emitted summaries
     */
    public void record(String reason, long count, Supplier<String> contextSupplier) {
        if (count <= 0) {
            return;
        }
        String key = normalizeReason(reason);
        totals.computeIfAbsent(key, ignored -> new LongAdder()).add(count);
        maybeEmit(contextSupplier);
    }

    private void maybeEmit(Supplier<String> contextSupplier) {
        long now = clockMs.getAsLong();
        if (firstEmissionDone.compareAndSet(false, true)) {
            lastEmissionMs.set(now);
            emit(contextSupplier);
            return;
        }
        long previous = lastEmissionMs.get();
        if (now - previous < intervalMs) {
            return;
        }
        if (lastEmissionMs.compareAndSet(previous, now)) {
            emit(contextSupplier);
        }
    }

    private void emit(Supplier<String> contextSupplier) {
        StringBuilder message = new StringBuilder(160);
        message.append('[').append(component).append("] Overflow summary: ");
        boolean first = true;
        for (Map.Entry<String, Long> entry : snapshotTotals().entrySet()) {
            if (!first) {
                message.append(", ");
            }
            message.append(entry.getKey()).append('=').append(entry.getValue());
            first = false;
        }
        String context = contextSupplier == null ? "" : contextSupplier.get();
        if (context != null && !context.isBlank()) {
            message.append("; ").append(context.trim());
        }
        logSink.accept(message.toString());
    }

    private Map<String, Long> snapshotTotals() {
        Map<String, Long> snapshot = new TreeMap<>();
        totals.forEach((key, value) -> snapshot.put(key, value.sum()));
        return snapshot;
    }

    private static String normalizeReason(String reason) {
        if (reason == null || reason.isBlank()) {
            return "unknown";
        }
        String trimmed = reason.trim();
        StringBuilder normalized = new StringBuilder(trimmed.length());
        for (int i = 0; i < trimmed.length(); i++) {
            char ch = trimmed.charAt(i);
            if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_'
                    || ch == '.'
                    || ch == '-') {
                normalized.append(ch);
            } else {
                normalized.append('_');
            }
        }
        return normalized.toString();
    }
}
