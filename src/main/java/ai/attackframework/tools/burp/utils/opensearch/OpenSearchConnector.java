package ai.attackframework.tools.burp.utils.opensearch;

import java.net.URI;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.hc.core5.http.HttpHost;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.transport.OpenSearchTransport;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5TransportBuilder;

/**
 * Factory/cache for OpenSearch clients.
 *
 * <p>Ownership:
 * Clients are cached per base URL and reused. Do not close the returned client;
 * lifecycle is managed here.</p>
 */
public final class OpenSearchConnector {

    private static final ConcurrentHashMap<String, OpenSearchClient> clientCache = new ConcurrentHashMap<>();

    private OpenSearchConnector() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns a cached client for the given base URL, creating it on first use.
     *
     * @param baseUrl e.g., http://localhost:9200
     * @return shared client
     * @throws OpenSearchClientBuildException when the client cannot be constructed
     */
    public static OpenSearchClient getClient(String baseUrl) {
        return clientCache.computeIfAbsent(baseUrl, OpenSearchConnector::buildClient);
    }

    private static OpenSearchClient buildClient(String baseUrl) {
        try {
            URI uri = URI.create(baseUrl);
            HttpHost host = new HttpHost(uri.getScheme(), uri.getHost(), uri.getPort());
            JsonpMapper mapper = new JacksonJsonpMapper();

            OpenSearchTransport transport = ApacheHttpClient5TransportBuilder
                    .builder(host)
                    .setMapper(mapper)
                    .build();

            return new OpenSearchClient(transport);
        } catch (Exception e) {
            throw new OpenSearchClientBuildException("Failed to build OpenSearch client for " + baseUrl, e);
        }
    }
}
