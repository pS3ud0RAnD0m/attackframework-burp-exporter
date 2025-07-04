package ai.attackframework.vectors.sources.burp.utils.opensearch;

import org.apache.http.HttpHost;
import org.opensearch.client.RestClient;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.transport.rest_client.RestClientTransport;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;

public class OpenSearchConnector {

    public static OpenSearchClient getClient(String baseUrl) throws Exception {
        HttpHost host = parseHost(baseUrl);
        RestClient restClient = RestClient.builder(host).build();
        RestClientTransport transport = new RestClientTransport(restClient, new JacksonJsonpMapper());
        return new OpenSearchClient(transport);
    }

    private static HttpHost parseHost(String baseUrl) throws Exception {
        java.net.URI uri = java.net.URI.create(baseUrl);
        String scheme = uri.getScheme();
        String host = uri.getHost();
        int port = uri.getPort() != -1 ? uri.getPort() : (scheme.equals("https") ? 443 : 80);

        if (host == null || scheme == null) {
            throw new IllegalArgumentException("Invalid OpenSearch URL: " + baseUrl);
        }

        return new HttpHost(host, port, scheme);
    }
}
