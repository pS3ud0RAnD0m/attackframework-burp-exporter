package ai.attackframework.tools.burp.sinks;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;
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
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Scanner;

public class OpenSearchSink {

    private static final String MAPPINGS_PATH = "/opensearch/mappings/";

    public static IndexResult createIndexFromResource(String baseUrl, String shortName) {
        String fullIndexName = shortName.equals("tool")
                ? IndexNaming.INDEX_PREFIX
                : IndexNaming.INDEX_PREFIX + "-" + shortName;

        String mappingFile = MAPPINGS_PATH + shortName + ".json";

        Logger.logInfo("Attempting to create index: " + fullIndexName);
        Logger.logInfo("Using mapping file: " + mappingFile);

        String jsonBody = null;

        try {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);

            boolean exists = client.indices().exists(b -> b.index(fullIndexName)).value();
            if (exists) {
                Logger.logInfo("Index already exists: " + fullIndexName);
                return new IndexResult(shortName, fullIndexName, IndexResult.Status.EXISTS);
            }

            try (InputStream is = OpenSearchSink.class.getResourceAsStream(mappingFile)) {
                if (is == null) {
                    Logger.logError("Mapping file not found: " + mappingFile);
                    return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED);
                }
                jsonBody = new Scanner(is, StandardCharsets.UTF_8).useDelimiter("\\A").next();
            }

            JsonReader reader = Json.createReader(new StringReader(jsonBody));
            JsonObject root = reader.readObject();

            JsonObject settingsJson = root.getJsonObject("settings");
            JsonObject mappingsJson = root.getJsonObject("mappings");

            if (settingsJson == null || mappingsJson == null) {
                Logger.logError("Mapping file must contain both 'settings' and 'mappings'.");
                return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED);
            }

            @SuppressWarnings("resource") // client owns transport, do not close here
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

            CreateIndexResponse response = client.indices().create(request);
            Logger.logInfo("Index creation acknowledged: " + response.acknowledged());

            return new IndexResult(shortName, fullIndexName,
                    response.acknowledged() ? IndexResult.Status.CREATED : IndexResult.Status.FAILED);

        } catch (Exception e) {
            Logger.logError("Exception while creating index: " + fullIndexName);
            if (jsonBody != null) Logger.logError("Mapping JSON:\n" + jsonBody);
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logError(sw.toString());
            return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED);
        }
    }

    public static List<IndexResult> createSelectedIndexes(String baseUrl, List<String> selectedSources) {
        Logger.logInfo("Entered createSelectedIndexes with sources: " + selectedSources);

        // Derive short names from the shared naming logic and always include "tool".
        List<String> baseNames = IndexNaming.computeIndexBaseNames(selectedSources);
        LinkedHashSet<String> shortNames = new LinkedHashSet<>();
        for (String base : baseNames) {
            if (base.equals(IndexNaming.INDEX_PREFIX)) {
                shortNames.add("tool");
            } else if (base.startsWith(IndexNaming.INDEX_PREFIX + "-")) {
                shortNames.add(base.substring(IndexNaming.INDEX_PREFIX.length() + 1));
            }
        }

        List<IndexResult> results = new ArrayList<>();
        for (String shortName : shortNames) {
            Logger.logInfo("Creating index for: " + shortName);
            IndexResult result = createIndexFromResource(baseUrl, shortName);
            Logger.logInfo("Result for " + shortName + ": " + result.status());
            results.add(result);
        }
        return results;
    }

    public record IndexResult(String shortName, String fullName, Status status) {
        public enum Status { CREATED, EXISTS, FAILED }
    }
}
