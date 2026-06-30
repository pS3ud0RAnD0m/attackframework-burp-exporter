package ai.anomalousvectors.tools.burp.utils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe map-of-counters keyed by a short reason label.
 *
 * <p>Used wherever we want a small, reason-coded event tally (silent skips, traffic drops,
 * ...). Keys are trimmed; {@code null}, blank, or non-positive counts are ignored so that
 * hot-path callers do not need to guard each call. Snapshots are returned in a deterministic
 * key order so the UI can render stable rows.</p>
 */
public final class ReasonCounterSet {

    private final Map<String, AtomicLong> counters = new ConcurrentHashMap<>();

    /** Adds {@code count} to the counter for {@code reason}; ignored when inputs are invalid. */
    public void record(String reason, long count) {
        if (reason == null || count <= 0) {
            return;
        }
        String key = reason.trim();
        if (key.isEmpty()) {
            return;
        }
        counters.computeIfAbsent(key, k -> new AtomicLong(0L)).addAndGet(count);
    }

    /** Returns the counter for {@code reason}, or {@code 0} when the key is absent or invalid. */
    public long get(String reason) {
        if (reason == null) {
            return 0L;
        }
        String key = reason.trim();
        if (key.isEmpty()) {
            return 0L;
        }
        AtomicLong counter = counters.get(key);
        return counter == null ? 0L : counter.get();
    }

    /**
     * Returns a sorted-by-key snapshot of the counters. The returned map is a live copy and
     * may be iterated without synchronization; later updates are not reflected.
     */
    public Map<String, Long> snapshot() {
        Map<String, Long> out = new LinkedHashMap<>();
        counters.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> out.put(e.getKey(), e.getValue().get()));
        return out;
    }

    /** Returns the sum across every counter; zero when the set is empty. */
    public long total() {
        long sum = 0L;
        for (AtomicLong counter : counters.values()) {
            sum += counter.get();
        }
        return sum;
    }

    /** Removes all counters. */
    public void clear() {
        counters.clear();
    }
}
