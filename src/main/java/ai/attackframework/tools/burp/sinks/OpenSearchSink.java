package ai.attackframework.tools.burp.sinks;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.stream.JsonParser;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;
import org.opensearch.client.opensearch.indices.CreateIndexResponse;
import org.opensearch.client.opensearch.indices.IndexSettings;
import org.opensearch.client.opensearch._types.mapping.TypeMapping;

import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Creates OpenSearch indices from bundled JSON mapping files.
 *
 * <p>Clients are obtained via {@link OpenSearchConnector} and must not be closed here.</p>
 */
public class OpenSearchSink {

    private static final String DEFAULT_MAPPINGS_RESOURCE_ROOT = "/opensearch/mappings/";

    /** Creates an index from {@code /opensearch/mappings/<shortName>.json}. */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName) {
        final String root = System.getProperty("attackframework.mappings.root", DEFAULT_MAPPINGS_RESOURCE_ROOT);
        return createIndexFromResource(baseUrl, shortName, root);
    }

    /** Creates an index from {@code <mappingsResourceRoot>/<shortName>.json}. */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName, String mappingsResourceRoot) {
        final String resourceRoot = (mappingsResourceRoot == null || mappingsResourceRoot.isBlank())
                ? DEFAULT_MAPPINGS_RESOURCE_ROOT
                : mappingsResourceRoot;

        final String fullIndexName = shortName.equals("tool")
                ? IndexNaming.INDEX_PREFIX
                : IndexNaming.INDEX_PREFIX + "-" + shortName;

        final String mappingFile = resourceRoot + shortName + ".json";

        Logger.logInfo("Attempting to create index: " + fullIndexName);
        Logger.logInfo("Using mapping file: " + mappingFile);

        String jsonBody = null;

        try {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);

            boolean exists = client.indices().exists(b -> b.index(fullIndexName)).value();
            if (exists) {
                Logger.logInfo("Index already exists: " + fullIndexName);
                return new IndexResult(shortName, fullIndexName, IndexResult.Status.EXISTS, null);
            }

            try (InputStream is = OpenSearchSink.class.getResourceAsStream(mappingFile)) {
                if (is == null) {
                    String reason = "Mapping file not found: " + mappingFile;
                    Logger.logError(reason);
                    return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, reason);
                }
                jsonBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            JsonObject root;
            try (JsonReader reader = Json.createReader(new StringReader(jsonBody))) {
                root = reader.readObject();
            }

            JsonObject settingsJson = root.getJsonObject("settings");
            JsonObject mappingsJson = root.getJsonObject("mappings");

            if (settingsJson == null || mappingsJson == null) {
                String reason = "Mapping JSON must contain both 'settings' and 'mappings'.";
                Logger.logError(reason);
                return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, reason);
            }

            // Local mapper for static JSON content (avoid touching client transport).
            JsonpMapper mapper = new JacksonJsonpMapper();

            IndexSettings settings;
            try (JsonParser settingsParser = Json.createParser(new StringReader(settingsJson.toString()))) {
                settings = IndexSettings._DESERIALIZER.deserialize(settingsParser, mapper);
            }

            TypeMapping mappings;
            try (JsonParser mappingsParser = Json.createParser(new StringReader(mappingsJson.toString()))) {
                mappings = TypeMapping._DESERIALIZER.deserialize(mappingsParser, mapper);
            }

            CreateIndexRequest request = new CreateIndexRequest.Builder()
                    .index(fullIndexName)
                    .settings(settings)
                    .mappings(mappings)
                    .build();

            CreateIndexResponse response = client.indices().create(request);
            Logger.logInfo("Index creation acknowledged: " + response.acknowledged());

            return new IndexResult(
                    shortName,
                    fullIndexName,
                    response.acknowledged() ? IndexResult.Status.CREATED : IndexResult.Status.FAILED,
                    response.acknowledged() ? null : "Create not acknowledged"
            );

        } catch (Exception e) {
            Logger.logError("Exception while creating index: " + fullIndexName);
            if (jsonBody != null) Logger.logError("Mapping JSON:\n" + jsonBody);
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logError(sw.toString().stripTrailing());

            String reason = conciseRootCause(e);
            return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, reason);
        }
    }

    /** Creates all indices required by the selected sources; always includes "tool". */
    public static List<IndexResult> createSelectedIndexes(String baseUrl, List<String> selectedSources) {
        Logger.logInfo("Entered createSelectedIndexes with sources: " + selectedSources);

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

    /** Compact root-cause message, capped for UI status. */
    private static String conciseRootCause(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null) c = c.getCause();
        String msg = c.getMessage();
        if (msg == null || msg.isBlank()) msg = c.getClass().getSimpleName();
        msg = msg.replaceAll("[\\r\\n]+", " ").trim();
        if (msg.length() > 300) msg = msg.substring(0, 300);
        return msg;
    }

    /**
     * Result of an index creation attempt.
     *
     * @param shortName logical name used to select the mapping file
     * @param fullName  fully-qualified index name
     * @param status    CREATED, EXISTS, or FAILED
     * @param error     concise reason when {@code status == FAILED}; otherwise {@code null}
     */
    public record IndexResult(String shortName, String fullName, Status status, String error) {
        public enum Status { CREATED, EXISTS, FAILED }
    }
}
