/**
 * OpenSearch transport utilities shared by all sinks that push to OpenSearch.
 *
 * <p>Two bulk entry points serve different workloads:</p>
 * <ul>
 *   <li>{@link ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper#pushBulk}
 *       — retry-coordinated bulk push used by one-shot snapshot reporters (Proxy History,
 *       Sitemap, Findings). Integrates with
 *       {@link ai.attackframework.tools.burp.utils.opensearch.IndexingRetryCoordinator} so
 *       transient failures pause inbound work and later retry queued batches without
 *       double-counting.</li>
 *   <li>{@link ai.attackframework.tools.burp.utils.opensearch.ChunkedBulkSender} — streaming
 *       drain used by the live traffic queue
 *       ({@link ai.attackframework.tools.burp.sinks.TrafficExportQueue}). Writes NDJSON
 *       incrementally to avoid holding large batches in memory for Proxy and Repeater live
 *       traffic.</li>
 * </ul>
 *
 * <p>Batch sizing is governed by
 * {@link ai.attackframework.tools.burp.utils.opensearch.BatchSizeController}, which adapts to
 * observed bulk latency to keep pushes within a safe size/time envelope. Both bulk paths share
 * this controller so sustained backpressure applies uniformly across reporters.</p>
 *
 * <p>Snapshot and live paths both converge on
 * {@link ai.attackframework.tools.burp.sinks.FileExportService} for file output and on
 * {@link ai.attackframework.tools.burp.sinks.BulkOutcomeRecorder} /
 * {@link ai.attackframework.tools.burp.sinks.TrafficRouteBucket} for counter accounting so
 * stats remain consistent regardless of which bulk strategy runs.</p>
 */
package ai.attackframework.tools.burp.utils.opensearch;
