/**
 * Data sinks that persist exported Burp Suite data.
 *
 * <p>Implementations handle I/O concerns such as writing JSON files or pushing documents to
 * OpenSearch. They avoid Swing dependencies; callers supply configuration and invoke them from
 * background threads.</p>
 */
package ai.attackframework.tools.burp.sinks;
