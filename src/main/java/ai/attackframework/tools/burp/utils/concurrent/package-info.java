/**
 * Concurrency helpers shared by sinks, UI, and retry paths.
 *
 * <p>Contains small utilities that every extension-owned background worker uses so lifecycle
 * semantics stay consistent across UI stop and extension unload:</p>
 * <ul>
 *   <li>{@link ai.attackframework.tools.burp.utils.concurrent.Workers} centralizes the
 *       "{@code shutdownNow} + {@code awaitTermination}" and "{@code interrupt} + {@code join}"
 *       patterns for {@link java.util.concurrent.ExecutorService} and raw
 *       {@link java.lang.Thread} owners.</li>
 *   <li>{@link ai.attackframework.tools.burp.utils.concurrent.LazyScheduler} owns the
 *       "{@code volatile} field + {@code synchronized} ensure-started + {@link
 *       ai.attackframework.tools.burp.utils.concurrent.Workers} shutdown" pattern used by every
 *       reporter and by the orphan-flush path so lazy start and deterministic teardown are
 *       implemented in one place.</li>
 * </ul>
 */
package ai.attackframework.tools.burp.utils.concurrent;
