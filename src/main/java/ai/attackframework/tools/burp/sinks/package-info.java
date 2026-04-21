/**
 * Export sinks and related reporters for Burp Suite data.
 *
 * <p>This package contains the document builders, queues, and OpenSearch/file sinks that persist
 * exporter data, along with best-effort reporters that bridge Burp APIs into those sinks. Most
 * types operate on background threads, but some Repeater-history helpers necessarily inspect Swing
 * state on the EDT because Montoya does not expose a dedicated historic Repeater API.</p>
 */
package ai.attackframework.tools.burp.sinks;
