package ai.attackframework.tools.burp.testutils;

import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Shared reachability check for the OpenSearch dev instance used by integration tests.
 * Performs a single connection attempt per JVM and caches the result so all integration
 * tests that depend on OpenSearch can skip immediately when the cluster is unreachable
 * (e.g. on CI where {@value #BASE_URL} is not available), avoiding repeated timeouts
 * and noisy skip messages.
 */
public final class OpenSearchReachable {

    /** Base URL of the OpenSearch instance used by integration tests (internal/dev only). */
    public static final String BASE_URL = "http://opensearch.url:9200";

    private static volatile Boolean cached = null;

    private OpenSearchReachable() {}

    /**
     * Returns whether the OpenSearch dev cluster at {@link #BASE_URL} is reachable.
     * The first call performs the check; subsequent calls return the cached result.
     */
    public static boolean isReachable() {
        if (cached == null) {
            synchronized (OpenSearchReachable.class) {
                if (cached == null) {
                    cached = OpenSearchClientWrapper.testConnection(BASE_URL).success();
                }
            }
        }
        return cached;
    }
}
