package ai.attackframework.tools.burp.utils.opensearch;

import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Classifies OpenSearch push outcomes that are expected when the user stops export or pooled
 * clients are torn down, so they are not surfaced as destination failures.
 */
public final class OpenSearchPushCancellation {

    private OpenSearchPushCancellation() {}

    /**
     * Returns {@code true} when export is no longer running (user Stop or lifecycle reset).
     */
    public static boolean isUserStopInProgress() {
        return !RuntimeConfig.isExportRunning();
    }

    /**
     * Returns {@code true} when a push failure should not increment stats, set last-error text,
     * or emit panel warnings — typically because Stop was clicked or connectors are shutting down.
     */
    public static boolean shouldSuppressFailureAccounting() {
        return isUserStopInProgress();
    }

    /**
     * Returns {@code true} when {@code throwable} matches common Stop/teardown interruption causes.
     *
     * @param throwable failure from an in-flight push; {@code null} checks export-stopped state only
     * @return {@code true} for interrupted I/O or connector shutdown messages
     */
    public static boolean isBenignShutdownCause(Throwable throwable) {
        if (throwable == null) {
            return isUserStopInProgress();
        }
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current instanceof InterruptedException) {
                return true;
            }
            String message = current.getMessage();
            if (message != null && matchesBenignShutdownMessage(message)) {
                return true;
            }
        }
        return Thread.currentThread().isInterrupted() && isUserStopInProgress();
    }

    /**
     * Returns {@code true} when a push exception should be logged quietly and not treated as an
     * indexing failure.
     *
     * @param throwable push failure; may be {@code null}
     * @return {@code true} to log at TRACE and skip failure accounting
     */
    public static boolean shouldSuppressPushFailure(Throwable throwable) {
        return shouldSuppressFailureAccounting() || isBenignShutdownCause(throwable);
    }

    /**
     * Returns a short description for TRACE logs when a bulk/document push was cancelled during Stop.
     *
     * @param throwable push failure; may be {@code null}
     * @return human-readable suffix (never {@code null})
     */
    public static String cancelledPushLogSuffix(Throwable throwable) {
        if (isUserStopInProgress()) {
            return "export stopped";
        }
        String message = rootMessage(throwable);
        return message.isBlank() ? "connector shut down" : message;
    }

    private static String rootMessage(Throwable throwable) {
        if (throwable == null) {
            return "";
        }
        Throwable root = throwable;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        String message = root.getMessage();
        return message == null ? root.getClass().getSimpleName() : message;
    }

    private static boolean matchesBenignShutdownMessage(String message) {
        String lower = message.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("interrupted")
                || lower.contains("i/o reactor has been shut down")
                || lower.contains("connection is closed")
                || lower.contains("connection pool shut down")
                || lower.contains("pool shut down")
                || lower.contains("socket closed");
    }
}
