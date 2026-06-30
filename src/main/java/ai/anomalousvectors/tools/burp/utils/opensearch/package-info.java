/**
 * OpenSearch transport utilities shared by all sinks that push to OpenSearch.
 *
 * <p>Three bulk strategies serve different workloads:</p>
 * <ul>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.opensearch.PreparedBulkSender} and
 *       {@link ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper#pushPreparedBulk}
 *       — pre-serialized NDJSON over raw HTTP. Used by
 *       {@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine} snapshot
 *       reporters (Proxy History, Sitemap initial, Findings backlog, Proxy WebSocket historic)
 *       and by the {@link ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator}
 *       drain thread after re-prepare.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.opensearch.ChunkedBulkSender} — streaming
 *       drain used by the live traffic queue
 *       ({@link ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue}). Reuses
 *       {@code bulkNdjsonBytes} from prepare when posting each chunk.</li>
 *   <li>{@link ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper#doPushBulkWithDetails}
 *       — Java-client {@code BulkRequest} fallback for callers without pre-serialized bytes.</li>
 * </ul>
 *
 * <p>Batch sizing is governed by
 * {@link ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController} for live traffic and
 * most incremental reporters. Proxy History snapshot uses local chunk targets (100–1500) with
 * live-queue and GC backpressure.</p>
 *
 * <p>All paths share
 * {@link ai.anomalousvectors.tools.burp.utils.opensearch.BulkNdjsonResponseParser} for per-item
 * failure logging and converge on {@link ai.anomalousvectors.tools.burp.sinks.FileExportService}
 * for file output.</p>
 */
package ai.anomalousvectors.tools.burp.utils.opensearch;
