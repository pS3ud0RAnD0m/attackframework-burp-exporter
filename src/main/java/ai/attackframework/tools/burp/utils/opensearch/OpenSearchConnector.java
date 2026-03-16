package ai.attackframework.tools.burp.utils.opensearch;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.concurrent.ConcurrentHashMap;

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
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
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
        String key = cacheKey(baseUrl, username, password, insecure);
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
        String key = cacheKey(baseUrl, username, password, insecure);
        return classicClientCache.computeIfAbsent(
                key, k -> buildClassicClient(baseUrl, username, password, insecure));
    }

    private static final String INSECURE_PROP = "OPENSEARCH_INSECURE";

    static boolean isInsecureEnabled() {
        return "true".equalsIgnoreCase(System.getProperty(INSECURE_PROP, "").trim())
                || RuntimeConfig.openSearchInsecureSsl();
    }

    private static String cacheKey(String baseUrl, String username, String password, boolean insecure) {
        String cred = (username == null && password == null) ? "" : "|" + (username != null ? username : "") + "|" + (password != null ? password : "");
        return baseUrl + cred + "|insecure=" + insecure;
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
                if (insecure && useHttps) {
                    try {
                        SSLContext sslContext = SSLContextBuilder.create()
                                .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                                .build();
                        connManagerBuilder.setTlsStrategy(ClientTlsStrategyBuilder.create()
                                .setSslContext(sslContext)
                                .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                                .buildAsync());
                    } catch (GeneralSecurityException e) {
                        throw new OpenSearchClientBuildException("Failed to build trust-all SSL context", e);
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

            if (insecure && useHttps) {
                SSLContext sslContext = SSLContextBuilder.create()
                        .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                        .build();
                connManagerBuilder.setTlsSocketStrategy(ClientTlsStrategyBuilder.create()
                        .setSslContext(sslContext)
                        .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                        .buildClassic());
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
}
