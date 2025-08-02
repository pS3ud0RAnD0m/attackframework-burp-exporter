package ai.attackframework.vectors.sources.burp.utils.opensearch;

import org.apache.hc.core5.http.HttpHost;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.transport.OpenSearchTransport;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5TransportBuilder;

import java.net.URI;
import java.util.concurrent.ConcurrentHashMap;

public class OpenSearchConnector {

    private static final ConcurrentHashMap<String, OpenSearchClient> clientCache = new ConcurrentHashMap<>();

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
            throw new RuntimeException("❌ Failed to build OpenSearch client for " + baseUrl + ": " + e.getMessage(), e);
        }
    }
}
