package ai.attackframework.vectors.sources.burp.sinks;

import ai.attackframework.vectors.sources.burp.utils.Logger;
import ai.attackframework.vectors.sources.burp.utils.opensearch.OpenSearchConnector;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.stream.JsonParser;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;
import org.opensearch.client.opensearch.indices.CreateIndexResponse;
import org.opensearch.client.opensearch.indices.IndexSettings;
import org.opensearch.client.opensearch._types.mapping.TypeMapping;
import org.opensearch.client.transport.Transport;

import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Scanner;

public class OpenSearchSink {

    private static final String INDEX_PREFIX = "attackframework-burp-";
    private static final String MAPPINGS_PATH = "/opensearch/mappings/";

    public static boolean createIndexFromResource(String baseUrl, String shortName) {
        String fullIndexName = INDEX_PREFIX + shortName;
        String mappingFile = MAPPINGS_PATH + shortName + ".json";

        Logger.logInfo("🔍 Attempting to create index: " + fullIndexName);
        Logger.logInfo("📄 Using mapping file: " + mappingFile);

        String jsonBody = null;

        try {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);

            try (InputStream is = OpenSearchSink.class.getResourceAsStream(mappingFile)) {
                if (is == null) {
                    Logger.logError("❌ MAPPING FILE NOT FOUND: " + mappingFile);
                    return false;
                }
                Logger.logInfo("✅ Found mapping file for: " + shortName);
                jsonBody = new Scanner(is, StandardCharsets.UTF_8).useDelimiter("\\A").next();
            }

            JsonReader reader = Json.createReader(new StringReader(jsonBody));
            JsonObject root = reader.readObject();

            JsonObject settingsJson = root.getJsonObject("settings");
            JsonObject mappingsJson = root.getJsonObject("mappings");

            if (settingsJson == null || mappingsJson == null) {
                Logger.logError("❌ Mapping file must contain both 'settings' and 'mappings'.");
                return false;
            }

            @SuppressWarnings("resource")
            Transport transport = client._transport();
            JsonpMapper mapper = transport.jsonpMapper();

            JsonParser settingsParser = Json.createParser(new StringReader(settingsJson.toString()));
            IndexSettings settings = IndexSettings._DESERIALIZER.deserialize(settingsParser, mapper);

            JsonParser mappingsParser = Json.createParser(new StringReader(mappingsJson.toString()));
            TypeMapping mappings = TypeMapping._DESERIALIZER.deserialize(mappingsParser, mapper);

            CreateIndexRequest request = new CreateIndexRequest.Builder()
                    .index(fullIndexName)
                    .settings(settings)
                    .mappings(mappings)
                    .build();

            Logger.logInfo("📡 Sending CreateIndex request for: " + fullIndexName);
            CreateIndexResponse response = client.indices().create(request);
            Logger.logInfo("✅ Index creation acknowledged: " + response.acknowledged());
            return response.acknowledged();

        } catch (Exception e) {
            Logger.logError("❌ Exception while creating index: " + fullIndexName);
            if (jsonBody != null) {
                Logger.logError("📄 Mapping JSON:\n" + jsonBody);
            }
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logError(sw.toString());
            return false;
        }
    }

    public static void createSelectedIndexes(String baseUrl, List<String> selectedSources) {
        Logger.logInfo("▶ Entered createSelectedIndexes with sources: " + selectedSources);
        for (String shortName : selectedSources) {
            Logger.logInfo("→ Creating index for: " + shortName);
            boolean ok = createIndexFromResource(baseUrl, shortName);
            Logger.logInfo("← Result for " + shortName + ": " + ok);
        }
    }
}
