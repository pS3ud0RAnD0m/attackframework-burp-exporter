package ai.attackframework.tools.burp.utils.concurrent;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Shared shutdown helpers for extension-owned background workers.
 *
 * <p>Centralizes the two termination patterns used across sinks, UI, and retry paths:</p>
 * <ul>
 *   <li>{@link #awaitExecutorShutdown(ExecutorService, long)} for {@link ExecutorService}
 *       owners (cancel queued work, wait briefly for in-flight tasks to exit).</li>
 *   <li>{@link #awaitThreadJoin(Thread, long)} for raw {@link Thread} owners
 *       (interrupt the worker, wait briefly for it to exit its run loop).</li>
 * </ul>
 *
 * <p>Both helpers are no-ops on {@code null}, swallow no other exceptions, and restore the
 * current thread's interrupt flag when the wait is interrupted. Callers are expected to have
 * already swapped the owning reference to {@code null} under their own lock so lazy restart
 * (on the next write) is the path forward after shutdown.</p>
 */
public final class Workers {

    /**
     * Default maximum milliseconds {@link #awaitExecutorShutdown} and {@link #awaitThreadJoin}
     * callers wait for termination before returning.
     *
     * <p>One second matches the historical per-owner budget used across sinks, UI, and retry
     * paths. Chosen to keep extension unload responsive while still giving in-flight work a
     * reasonable window to exit. Exposed as a single source of truth so every
     * {@link LazyScheduler} and every raw {@link ExecutorService} owner agrees on the same
     * shutdown semantics.</p>
     */
    public static final long DEFAULT_SHUTDOWN_TIMEOUT_MS = 1_000L;

    private Workers() {}

    /**
     * Cancels queued work and waits briefly for {@code executor} to terminate.
     *
     * <p>Invokes {@link ExecutorService#shutdownNow()} and then
     * {@link ExecutorService#awaitTermination(long, TimeUnit)} for {@code timeoutMs}
     * milliseconds. If the wait is interrupted, the current thread's interrupt flag is
     * restored and the method returns without throwing.</p>
     *
     * @param executor executor to stop; ignored when {@code null}
     * @param timeoutMs maximum milliseconds to wait for termination; values {@code <= 0}
     *                  only request cancellation without waiting
     */
    public static void awaitExecutorShutdown(ExecutorService executor, long timeoutMs) {
        if (executor == null) {
            return;
        }
        executor.shutdownNow();
        if (timeoutMs <= 0) {
            return;
        }
        try {
            executor.awaitTermination(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Interrupts {@code worker} and waits briefly for it to exit.
     *
     * <p>Invokes {@link Thread#interrupt()} and then {@link Thread#join(long)} for
     * {@code timeoutMs} milliseconds. If the wait is interrupted, the current thread's
     * interrupt flag is restored and the method returns without throwing.</p>
     *
     * @param worker thread to stop; ignored when {@code null}
     * @param timeoutMs maximum milliseconds to wait for {@code join}; values {@code <= 0}
     *                  only signal interrupt without waiting
     */
    public static void awaitThreadJoin(Thread worker, long timeoutMs) {
        if (worker == null) {
            return;
        }
        worker.interrupt();
        if (timeoutMs <= 0) {
            return;
        }
        try {
            worker.join(timeoutMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
