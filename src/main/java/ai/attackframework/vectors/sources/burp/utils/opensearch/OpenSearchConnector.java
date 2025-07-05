package ai.attackframework.vectors.sources.burp.utils.opensearch;

import org.apache.hc.core5.http.HttpHost;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.transport.OpenSearchTransport;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5TransportBuilder;

import java.net.URI;

public class OpenSearchConnector {

    public static OpenSearchClient getClient(String baseUrl) {
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
            throw new RuntimeException("Failed to initialize OpenSearch client: " + e.getMessage(), e);
        }
    }
}
