/**
 * Concurrency helpers shared by sinks, UI, and retry paths.
 *
 * <p>Contains small utilities that every extension-owned background worker uses so lifecycle
 * semantics stay consistent across UI stop and extension unload:</p>
 * <ul>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.Workers} centralizes the
 *       "{@code shutdownNow} + {@code awaitTermination}" and "{@code interrupt} + {@code join}"
 *       patterns for {@link java.util.concurrent.ExecutorService} and raw
 *       {@link java.lang.Thread} owners.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler} owns the
 *       "{@code volatile} field + {@code synchronized} ensure-started + {@link
 *       ai.anomalousvectors.tools.burp.utils.concurrent.Workers} shutdown" pattern used by every
 *       reporter and by the orphan-flush path so lazy start and deterministic teardown are
 *       implemented in one place.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine} runs parallel
 *       {@code build + prepare} on worker threads with serial bulk flush on the assembly thread.
 *       Used by Proxy History, Sitemap initial, Findings backlog, and Proxy WebSocket historic
 *       snapshots.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotPacing} and
 *       {@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache} throttle and
 *       memoize scope checks during large one-shot exports.</li>
 * </ul>
 */
package ai.anomalousvectors.tools.burp.utils.concurrent;
