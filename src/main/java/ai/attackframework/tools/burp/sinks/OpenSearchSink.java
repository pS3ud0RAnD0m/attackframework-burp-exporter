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
 * OpenSearch sink for creating indices from bundled JSON mapping files.
 * <p>
 * Ownership model:
 * - The OpenSearchClient is managed by {@link OpenSearchConnector}; this class never closes it.
 * - JSON mapping files are read from the classpath and parsed locally before issuing create requests.
 */
public class OpenSearchSink {

    /**
     * Default classpath root for mapping files. Can be overridden at runtime via
     * the system property {@code attackframework.mappings.root}.
     */
    private static final String DEFAULT_MAPPINGS_RESOURCE_ROOT = "/opensearch/mappings/";

    /**
     * Creates an index using a mapping file named {@code <shortName>.json} located under the
     * mappings resource root. The resource root can be set via the system property
     * {@code attackframework.mappings.root}; otherwise {@link #DEFAULT_MAPPINGS_RESOURCE_ROOT} is used.
     *
     * @param baseUrl   OpenSearch base URL (e.g., http://host:9200)
     * @param shortName logical short name (e.g., "traffic", "findings", "sitemap", "tool")
     * @return result indicating CREATED, EXISTS, or FAILED
     */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName) {
        final String root = System.getProperty("attackframework.mappings.root", DEFAULT_MAPPINGS_RESOURCE_ROOT);
        return createIndexFromResource(baseUrl, shortName, root);
    }

    /**
     * Creates an index using a mapping file named {@code <shortName>.json} under the provided resource root.
     * This overload exists primarily for tests and specialized callers that need custom roots.
     *
     * @param baseUrl             OpenSearch base URL
     * @param shortName           logical short name (e.g., "traffic")
     * @param mappingsResourceRoot classpath root for mapping files (e.g., "/opensearch/mappings/")
     * @return result indicating CREATED, EXISTS, or FAILED
     */
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
            // Acquire shared client (do not close here).
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);

            boolean exists = client.indices().exists(b -> b.index(fullIndexName)).value();
            if (exists) {
                Logger.logInfo("Index already exists: " + fullIndexName);
                return new IndexResult(shortName, fullIndexName, IndexResult.Status.EXISTS);
            }

            // Read the mapping file into memory.
            try (InputStream is = OpenSearchSink.class.getResourceAsStream(mappingFile)) {
                if (is == null) {
                    Logger.logError("Mapping file not found: " + mappingFile);
                    return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED);
                }
                jsonBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            // Parse the root JSON once.
            JsonObject root;
            try (JsonReader reader = Json.createReader(new StringReader(jsonBody))) {
                root = reader.readObject();
            }

            JsonObject settingsJson = root.getJsonObject("settings");
            JsonObject mappingsJson = root.getJsonObject("mappings");

            if (settingsJson == null || mappingsJson == null) {
                Logger.logError("Mapping file must contain both 'settings' and 'mappings'.");
                return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED);
            }

            // Use a local mapper for deserialization of static JSON content to avoid touching client transport.
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
                    response.acknowledged() ? IndexResult.Status.CREATED : IndexResult.Status.FAILED
            );

        } catch (Exception e) {
            Logger.logError("Exception while creating index: " + fullIndexName);
            if (jsonBody != null) Logger.logError("Mapping JSON:\n" + jsonBody);
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logError(sw.toString());
            return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED);
        }
    }

    /**
     * Creates all indices required by the selected sources. Always includes the "tool" index.
     *
     * @param baseUrl         OpenSearch base URL
     * @param selectedSources list of source keys from which index base names are derived
     * @return result list in creation order
     */
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

    /**
     * Result of an index creation attempt.
     *
     * @param shortName logical name used to select the mapping file
     * @param fullName  fully-qualified index name
     * @param status    CREATED, EXISTS, or FAILED
     */
    public record IndexResult(String shortName, String fullName, Status status) {
        public enum Status { CREATED, EXISTS, FAILED }
    }
}
