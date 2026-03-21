package ai.attackframework.tools.burp.sinks;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/** Shared shutdown helper for reporter-owned executors. */
final class ReporterExecutors {
    private static final long SHUTDOWN_TIMEOUT_MS = 1_000;

    private ReporterExecutors() {}

    /**
     * Cancels queued work and waits briefly for the executor to terminate.
     *
     * <p>Interrupt status is restored if waiting is interrupted.</p>
     *
     * @param executor executor to stop; ignored when {@code null}
     */
    static void shutdownNowAndAwait(ExecutorService executor) {
        if (executor == null) {
            return;
        }
        executor.shutdownNow();
        try {
            executor.awaitTermination(SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
