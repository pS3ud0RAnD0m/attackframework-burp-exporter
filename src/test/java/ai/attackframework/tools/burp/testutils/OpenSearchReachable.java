package ai.attackframework.tools.burp.testutils;

import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Shared reachability check for the OpenSearch dev instance used by integration tests.
 * URL and optional credentials come from {@link OpenSearchTestConfig} (system properties or env). Performs a single connection attempt per JVM and
 * caches the result so all integration tests that depend on OpenSearch can skip
 * immediately when the cluster is unreachable (e.g. on CI), avoiding repeated timeouts.
 */
public final class OpenSearchReachable {

    /** Base URL for integration tests (from {@link OpenSearchTestConfig}). */
    public static final String BASE_URL = OpenSearchTestConfig.get().baseUrl();

    private static volatile Boolean cached = null;

    private OpenSearchReachable() {}

    /** Base URL (same as {@link #BASE_URL}; for consistency with credentials accessors). */
    public static String getBaseUrl() {
        return OpenSearchTestConfig.get().baseUrl();
    }

    /** Username for basic auth, or null (from {@link OpenSearchTestConfig}). */
    public static String getUsername() {
        return OpenSearchTestConfig.get().username();
    }

    /** Password for basic auth, or null (from {@link OpenSearchTestConfig}). */
    public static String getPassword() {
        return OpenSearchTestConfig.get().password();
    }

    /**
     * Convenience for {@link ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector#getClient(String, String, String)}
     * using URL and credentials from this config.
     */
    public static org.opensearch.client.opensearch.OpenSearchClient getClient() {
        OpenSearchTestConfig c = OpenSearchTestConfig.get();
        return ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector.getClient(
                c.baseUrl(), c.username(), c.password());
    }

    /**
     * Convenience for OpenSearchSink.createSelectedIndexes with credentials from this config.
     */
    public static java.util.List<ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult> createSelectedIndexes(
            java.util.List<String> selectedSources) {
        OpenSearchTestConfig c = OpenSearchTestConfig.get();
        return ai.attackframework.tools.burp.sinks.OpenSearchSink.createSelectedIndexes(
                c.baseUrl(), selectedSources, c.username(), c.password());
    }

    /**
     * Convenience for OpenSearchSink.createIndexFromResource with credentials from this config.
     */
    public static ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult createIndexFromResource(String shortName) {
        OpenSearchTestConfig c = OpenSearchTestConfig.get();
        return ai.attackframework.tools.burp.sinks.OpenSearchSink.createIndexFromResource(
                c.baseUrl(), shortName, null, c.username(), c.password());
    }

    /**
     * Returns whether the OpenSearch dev cluster at {@link #BASE_URL} is reachable.
     * Uses credentials from {@link OpenSearchTestConfig} when set. The first call
     * performs the check; subsequent calls return the cached result.
     */
    public static boolean isReachable() {
        if (cached == null) {
            synchronized (OpenSearchReachable.class) {
                if (cached == null) {
                    OpenSearchTestConfig config = OpenSearchTestConfig.get();
                    cached = OpenSearchClientWrapper.testConnection(
                            config.baseUrl(), config.username(), config.password()).success();
                }
            }
        }
        return cached;
    }
}
