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
 * <p>OpenSearch bulk exports use two deliberate paths: retry-coordinated snapshot pushes via
 * {@link ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper#pushBulk} and
 * streaming drains via
 * {@link ai.attackframework.tools.burp.utils.opensearch.ChunkedBulkSender}. Both converge on
 * {@link ai.attackframework.tools.burp.sinks.FileExportService} for file output and on
 * {@link ai.attackframework.tools.burp.sinks.TrafficRouteBucket} /
 * {@link ai.attackframework.tools.burp.sinks.BulkOutcomeRecorder} for counter accounting so
 * stats remain consistent across the two bulk strategies.</p>
 */
package ai.attackframework.tools.burp.sinks;
