package ai.attackframework.tools.burp.utils;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe counters and last error for traffic export to OpenSearch.
 *
 * <p>Updated by {@link ai.attackframework.tools.burp.sinks.OpenSearchTrafficHandler} on each
 * push; read by StatsPanel and by the tool-index stats snapshot task.</p>
 */
public final class TrafficExportStats {

    private static final AtomicLong SUCCESS_COUNT = new AtomicLong(0);
    private static final AtomicLong FAILURE_COUNT = new AtomicLong(0);
    private static final AtomicReference<String> LAST_ERROR = new AtomicReference<>(null);
    private static final int LAST_ERROR_MAX_LEN = 200;

    private TrafficExportStats() {}

    /** Increments the number of successful traffic document pushes. */
    public static void incrementSuccess() {
        SUCCESS_COUNT.incrementAndGet();
    }

    /** Increments the number of failed traffic document pushes. */
    public static void incrementFailure() {
        FAILURE_COUNT.incrementAndGet();
    }

    /**
     * Records the last push error message (truncated) for display in StatsPanel.
     *
     * @param message error message; null clears the last error
     */
    public static void setLastError(String message) {
        if (message == null || message.isEmpty()) {
            LAST_ERROR.set(null);
            return;
        }
        String truncated = message.length() <= LAST_ERROR_MAX_LEN
                ? message
                : message.substring(0, LAST_ERROR_MAX_LEN) + "...";
        LAST_ERROR.set(truncated);
    }

    /** Returns the current success count (number of traffic docs indexed). */
    public static long getSuccessCount() {
        return SUCCESS_COUNT.get();
    }

    /** Returns the current failure count (number of failed pushes). */
    public static long getFailureCount() {
        return FAILURE_COUNT.get();
    }

    /** Returns the last recorded error message, or null if none. */
    public static String getLastError() {
        return LAST_ERROR.get();
    }
}
