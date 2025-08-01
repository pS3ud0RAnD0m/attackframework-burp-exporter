package ai.attackframework.vectors.sources.burp.sinks;

import ai.attackframework.vectors.sources.burp.utils.opensearch.OpenSearchConnector;
import ai.attackframework.vectors.sources.burp.utils.Logger;
import jakarta.json.Json;
import jakarta.json.stream.JsonParser;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;
import org.opensearch.client.opensearch.indices.CreateIndexResponse;
import org.opensearch.client.transport.Transport;

import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Scanner;

public class OpenSearchSink {

    private static final String INDEX_PREFIX = "attackframework-burp-";
    private static final String MAPPINGS_PATH = "/opensearch/mappings/";

    public static boolean createIndexFromResource(String baseUrl, String shortName) {
        String fullIndexName = INDEX_PREFIX + shortName;
        String mappingFile = MAPPINGS_PATH + shortName + ".json";

        try {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);

            String jsonBody;
            try (InputStream is = OpenSearchSink.class.getResourceAsStream(mappingFile)) {
                if (is == null) throw new RuntimeException("Mapping file not found: " + mappingFile);
                jsonBody = new Scanner(is, StandardCharsets.UTF_8).useDelimiter("\\A").next();
            }

            JsonParser parser = Json.createParser(new StringReader(jsonBody));

            try (Transport transport = client._transport()) {
                CreateIndexRequest request = transport
                        .jsonpMapper()
                        .deserialize(parser, CreateIndexRequest.class)
                        .toBuilder()
                        .index(fullIndexName)
                        .build();

                CreateIndexResponse response = client.indices().create(request);
                return response.acknowledged();
            }

        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("resource_already_exists_exception")) {
                return true;
            }
            Logger.logError("Failed to create OpenSearch index: " + fullIndexName + "\n" + e);
            return false;
        }
    }

    public static void createSelectedIndexes(String baseUrl, List<String> selectedSources) {
        for (String shortName : selectedSources) {
            boolean ok = createIndexFromResource(baseUrl, shortName);
            if (ok) {
                Logger.logInfo("  ✔ Created or verified index: " + shortName);
            } else {
                Logger.logError("  ✖ Failed to create index: " + shortName);
            }
        }
    }
}
