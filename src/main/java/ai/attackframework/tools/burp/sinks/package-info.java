/**
 * Sinks (reporters) that turn Burp sources into exporter output for the OpenSearch and file sinks.
 *
 * <p>This package houses:</p>
 * <ul>
 *   <li><b>Traffic reporters</b> — {@link ai.attackframework.tools.burp.sinks.TrafficHttpHandler},
 *       {@link ai.attackframework.tools.burp.sinks.ProxyHistoryIndexReporter},
 *       {@link ai.attackframework.tools.burp.sinks.ProxyWebSocketIndexReporter},
 *       {@link ai.attackframework.tools.burp.sinks.ToolWebSocketLiveHandler},
 *       {@link ai.attackframework.tools.burp.sinks.RepeaterTabsIndexReporter} — that feed
 *       the shared {@code traffic} index.</li>
 *   <li><b>Non-traffic reporters</b> —
 *       {@link ai.attackframework.tools.burp.sinks.SitemapIndexReporter},
 *       {@link ai.attackframework.tools.burp.sinks.FindingsIndexReporter},
 *       {@link ai.attackframework.tools.burp.sinks.ExporterIndexConfigReporter} — that write
 *       their own domain indices.</li>
 *   <li><b>Shared infrastructure</b> —
 *       {@link ai.attackframework.tools.burp.sinks.TrafficExportQueue} bounded queue and spill,
 *       {@link ai.attackframework.tools.burp.sinks.FileExportService} file-sink writer,
 *       {@link ai.attackframework.tools.burp.sinks.TrafficRouteBucket} route mapping for
 *       traffic counters, {@link ai.attackframework.tools.burp.sinks.BulkOutcomeRecorder}
 *       bulk success/failure accounting,
 *       {@link ai.attackframework.tools.burp.sinks.SingleDocOutcomeRecorder} single-document
 *       success/failure accounting, and
 *       {@link ai.attackframework.tools.burp.sinks.SnapshotSummary} one-shot run summaries.</li>
 * </ul>
 *
 * <p>One-shot snapshot backlogs (Proxy History, Sitemap initial, Findings backlog, Proxy WebSocket
 * historic) use {@link ai.attackframework.tools.burp.utils.concurrent.SnapshotExportEngine} with
 * {@link ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper#pushPreparedBulk}
 * (pre-serialized NDJSON). Live traffic uses
 * {@link ai.attackframework.tools.burp.sinks.TrafficExportQueue} and
 * {@link ai.attackframework.tools.burp.utils.opensearch.ChunkedBulkSender}. Incremental reporters
 * (Sitemap 30s, Findings 30s) batch prepared documents directly. All paths converge on
 * {@link ai.attackframework.tools.burp.sinks.FileExportService} for file output.</p>
 */
package ai.attackframework.tools.burp.sinks;
