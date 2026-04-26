package ai.attackframework.tools.burp.utils.opensearch;

import ai.attackframework.tools.burp.utils.Logger;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http2.HttpVersionPolicy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.transport.OpenSearchTransport;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5TransportBuilder;

/**
 * Factory/cache for OpenSearch clients.
 *
 * <p>Ownership:
 * Clients are cached per base URL (and optional credentials) and reused. Do not close the returned client;
 * lifecycle is managed here.</p>
 */
public final class OpenSearchConnector {

    private static final ConcurrentHashMap<String, OpenSearchClient> clientCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, CloseableHttpClient> classicClientCache = new ConcurrentHashMap<>();

    private OpenSearchConnector() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns a cached client for the given base URL, creating it on first use (no auth).
     *
     * @param baseUrl e.g., https://opensearch.url:9200
     * @return shared client
     * @throws OpenSearchClientBuildException when the client cannot be constructed
     */
    public static OpenSearchClient getClient(String baseUrl) {
        return getClient(baseUrl, null, null);
    }

    /**
     * Returns a cached client for the given base URL and optional basic-auth credentials.
     * When both username and password are non-null and non-empty, basic auth is configured.
     *
     * @param baseUrl  e.g., https://opensearch.url:9200
     * @param username optional; null or empty to skip auth
     * @param password optional; null or empty to skip auth
     * @return shared client
     * @throws OpenSearchClientBuildException when the client cannot be constructed
     */
    public static OpenSearchClient getClient(String baseUrl, String username, String password) {
        boolean insecure = isInsecureEnabled();
        String key = cacheKey(baseUrl, username, password, insecure,
                OpenSearchTlsSupport.currentTlsMode(), OpenSearchTlsSupport.pinnedCertificateFingerprint());
        return clientCache.computeIfAbsent(key, k -> buildClient(baseUrl, username, password, insecure));
    }

    /**
     * Returns a cached classic HTTP client with the same TLS/auth behavior as {@link #getClient}.
     *
     * <p>Used by raw/chunked HTTP paths that call OpenSearch APIs directly, so they stay
     * behaviorally aligned with connector/test-connection.</p>
     */
    static CloseableHttpClient getClassicHttpClient(String baseUrl, String username, String password) {
        boolean insecure = isInsecureEnabled();
        String key = cacheKey(baseUrl, username, password, insecure,
                OpenSearchTlsSupport.currentTlsMode(), OpenSearchTlsSupport.pinnedCertificateFingerprint());
        return classicClientCache.computeIfAbsent(
                key, k -> buildClassicClient(baseUrl, username, password, insecure));
    }

    private static final String INSECURE_PROP = "OPENSEARCH_INSECURE";

    static boolean isInsecureEnabled() {
        return "true".equalsIgnoreCase(System.getProperty(INSECURE_PROP, "").trim())
                || OpenSearchTlsSupport.isInsecureMode();
    }

    private static String cacheKey(String baseUrl, String username, String password,
                                   boolean insecure, String tlsMode, String pinnedFingerprint) {
        String cred = (username == null && password == null) ? "" : "|" + (username != null ? username : "") + "|" + (password != null ? password : "");
        return baseUrl + cred + "|insecure=" + insecure + "|tls=" + tlsMode + "|pin=" + pinnedFingerprint;
    }

    private static OpenSearchClient buildClient(String baseUrl, String username, String password, boolean insecure) {
        try {
            URI uri = URI.create(baseUrl);
            HttpHost host = new HttpHost(uri.getScheme(), uri.getHost(), uri.getPort());
            JsonpMapper mapper = new JacksonJsonpMapper();

            ApacheHttpClient5TransportBuilder builder = ApacheHttpClient5TransportBuilder
                    .builder(host)
                    .setMapper(mapper);

            boolean useHttps = "https".equalsIgnoreCase(uri.getScheme());

            builder.setHttpClientConfigCallback(httpBuilder -> {
                PoolingAsyncClientConnectionManagerBuilder connManagerBuilder =
                        PoolingAsyncClientConnectionManagerBuilder.create()
                                .setDefaultTlsConfig(TlsConfig.custom()
                                        .setVersionPolicy(HttpVersionPolicy.NEGOTIATE)
                                        .build());
                if (hasCredentials(username, password)) {
                    BasicCredentialsProvider credsProvider = new BasicCredentialsProvider();
                    credsProvider.setCredentials(
                            new AuthScope(host),
                            new UsernamePasswordCredentials(username, password.toCharArray()));
                    httpBuilder.setDefaultCredentialsProvider(credsProvider);
                }
                if (useHttps) {
                    try {
                        if (insecure) {
                            SSLContext sslContext = SSLContextBuilder.create()
                                    .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                                    .build();
                            connManagerBuilder.setTlsStrategy(ClientTlsStrategyBuilder.create()
                                    .setSslContext(sslContext)
                                    .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                                    .buildAsync());
                        } else if (OpenSearchTlsSupport.isPinnedMode()) {
                            SSLContext sslContext = OpenSearchTlsSupport.buildPinnedSslContext();
                            connManagerBuilder.setTlsStrategy(ClientTlsStrategyBuilder.create()
                                    .setSslContext(sslContext)
                                    .buildAsync());
                        }
                    } catch (GeneralSecurityException e) {
                        throw new OpenSearchClientBuildException("Failed to build OpenSearch TLS context", e);
                    }
                }
                AsyncClientConnectionManager connManager = connManagerBuilder.build();
                httpBuilder.setConnectionManager(connManager);
                return httpBuilder;
            });

            OpenSearchTransport transport = builder.build();
            return new OpenSearchClient(transport);
        } catch (RuntimeException e) {
            throw new OpenSearchClientBuildException("Failed to build OpenSearch client for " + baseUrl, e);
        }
    }

    private static CloseableHttpClient buildClassicClient(
            String baseUrl, String username, String password, boolean insecure) {
        try {
            URI uri = URI.create(baseUrl);
            HttpHost host = new HttpHost(uri.getScheme(), uri.getHost(), uri.getPort());
            boolean useHttps = "https".equalsIgnoreCase(uri.getScheme());

            PoolingHttpClientConnectionManagerBuilder connManagerBuilder =
                    PoolingHttpClientConnectionManagerBuilder.create()
                            .setDefaultTlsConfig(TlsConfig.custom()
                                    .setVersionPolicy(HttpVersionPolicy.NEGOTIATE)
                                    .build());

            if (useHttps) {
                if (insecure) {
                    SSLContext sslContext = SSLContextBuilder.create()
                            .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                            .build();
                    connManagerBuilder.setTlsSocketStrategy(ClientTlsStrategyBuilder.create()
                            .setSslContext(sslContext)
                            .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                            .buildClassic());
                } else if (OpenSearchTlsSupport.isPinnedMode()) {
                    SSLContext sslContext = OpenSearchTlsSupport.buildPinnedSslContext();
                    connManagerBuilder.setTlsSocketStrategy(ClientTlsStrategyBuilder.create()
                            .setSslContext(sslContext)
                            .buildClassic());
                }
            }

            var httpBuilder = HttpClients.custom()
                    .setConnectionManager(connManagerBuilder.build());
            if (hasCredentials(username, password)) {
                BasicCredentialsProvider credsProvider = new BasicCredentialsProvider();
                credsProvider.setCredentials(
                        new AuthScope(host),
                        new UsernamePasswordCredentials(username, password.toCharArray()));
                httpBuilder.setDefaultCredentialsProvider(credsProvider);
            }
            return httpBuilder.build();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new OpenSearchClientBuildException(
                    "Failed to build classic OpenSearch HTTP client for " + baseUrl, e);
        }
    }

    private static boolean hasCredentials(String username, String password) {
        return username != null && !username.isBlank() && password != null && !password.isBlank();
    }

    /**
     * Closes every cached OpenSearch client and classic HTTP client, then clears both caches.
     *
     * <p>Each client owns a pooled connection manager, TLS session cache, and reactor/scheduler
     * threads that hold substantial off-heap state (direct {@code ByteBuffer}s, SSL session state).
     * Because the caches are {@code static}, those resources outlive any Stop/Start cycle unless
     * this method runs; otherwise they are released only on extension unload via classloader GC.</p>
     *
     * <p>Close exceptions are logged at debug and swallowed so a single misbehaving client cannot
     * prevent the other entries from being released. The method is idempotent: subsequent calls
     * on an already-empty cache are no-ops, and a later {@link #getClient(String)} rebuilds a
     * fresh client rather than returning a closed one.</p>
     */
    public static void closeAll() {
        AtomicInteger failures = new AtomicInteger();

        // Drain entries out of each cache *before* closing them. If we instead closed-then-cleared,
        // a concurrent getClient(...) call (e.g., the async stop-reclaim thread racing with a later
        // request) could observe an entry whose transport was already closed and return that
        // instance to the caller, surfacing as "Connection pool shut down" on the next request.
        List<Map.Entry<String, OpenSearchClient>> drainedClients = new ArrayList<>(clientCache.entrySet());
        clientCache.clear();
        for (Map.Entry<String, OpenSearchClient> entry : drainedClients) {
            try {
                entry.getValue()._transport().close();
            } catch (IOException | RuntimeException e) {
                failures.incrementAndGet();
                Logger.logDebug("OpenSearchConnector: failed to close transport for "
                        + redactKey(entry.getKey()) + ": "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            }
        }

        List<Map.Entry<String, CloseableHttpClient>> drainedClassic = new ArrayList<>(classicClientCache.entrySet());
        classicClientCache.clear();
        for (Map.Entry<String, CloseableHttpClient> entry : drainedClassic) {
            try {
                entry.getValue().close();
            } catch (IOException | RuntimeException e) {
                failures.incrementAndGet();
                Logger.logDebug("OpenSearchConnector: failed to close classic client for "
                        + redactKey(entry.getKey()) + ": "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            }
        }

        // Per-client failures land in the debug log (high-frequency tabs only). Promote a single
        // aggregate WARN to the panel so an operator who unloads the extension still sees that
        // not every cached client closed cleanly, without having to enable debug logging.
        int total = failures.get();
        if (total > 0) {
            Logger.logWarnPanelOnly("[OpenSearch] closeAll: " + total
                    + " cached client(s) failed to close cleanly; see debug log for details.");
        }
    }

    /**
     * Strips the credential segment from a cache key so it is safe to log. Package-private so
     * the redaction contract can be exercised directly without forcing real connection failures.
     */
    static String redactKey(String key) {
        if (key == null) {
            return "null";
        }
        int firstPipe = key.indexOf('|');
        if (firstPipe < 0) {
            return key;
        }
        int insecureMarker = key.indexOf("|insecure=");
        if (insecureMarker < 0 || insecureMarker <= firstPipe) {
            return key.substring(0, firstPipe);
        }
        return key.substring(0, firstPipe) + key.substring(insecureMarker);
    }
}
