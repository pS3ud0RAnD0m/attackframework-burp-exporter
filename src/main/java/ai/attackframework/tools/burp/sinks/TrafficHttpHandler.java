package ai.attackframework.tools.burp.sinks;

/**
 * Shared Burp HTTP traffic handler for live request/response export.
 *
 * <p>This sink-neutral type is the canonical public entry point for the extension's shared HTTP
 * traffic capture path. It keeps callers and user-facing docs on the neutral {@code Traffic}
 * vocabulary while the larger implementation remains isolated in
 * {@link TrafficHttpHandlerSupport}.</p>
 */
public class TrafficHttpHandler extends TrafficHttpHandlerSupport {}
