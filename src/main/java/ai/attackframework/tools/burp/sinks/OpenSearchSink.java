package ai.attackframework.tools.burp.sinks;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.function.BooleanSupplier;

import jakarta.json.Json;
import jakarta.json.JsonReader;
import jakarta.json.JsonObject;
import jakarta.json.JsonWriter;
import jakarta.json.stream.JsonParser;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.mapping.TypeMapping;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;
import org.opensearch.client.opensearch.indices.CreateIndexResponse;
import org.opensearch.client.opensearch.indices.IndexSettings;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;

/**
 * Creates OpenSearch indices from bundled JSON mapping files.
 *
 * <p>Clients are obtained via {@link OpenSearchConnector} and must not be closed here.</p>
 */
public class OpenSearchSink {

    private static final String DEFAULT_MAPPINGS_RESOURCE_ROOT = "/opensearch/mappings/";

    /** Creates an index from the bundled mapping resource for the logical index key. */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName) {
        final String root = System.getProperty("attackframework.mappings.root", DEFAULT_MAPPINGS_RESOURCE_ROOT);
        return createIndexFromResource(baseUrl, shortName, resolvedFullIndexName(shortName), root, null, null);
    }

    /** Creates an index from the bundled mapping resource for the logical index key. */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName, String mappingsResourceRoot) {
        return createIndexFromResource(baseUrl, shortName, resolvedFullIndexName(shortName), mappingsResourceRoot, null, null);
    }

    /**
     * Creates an index from the bundled mapping resource for the logical index key with optional basic auth.
     * When username and password are non-null and non-empty, uses basic auth for the request.
     */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName, String mappingsResourceRoot,
            String username, String password) {
        return createIndexFromResource(baseUrl, shortName, resolvedFullIndexName(shortName), mappingsResourceRoot, username, password);
    }

    /**
     * Creates an index from the bundled mapping resource for the logical index key with an explicit full name
     * and optional basic auth.
     */
    public static IndexResult createIndexFromResource(String baseUrl, String shortName, String fullIndexName, String mappingsResourceRoot,
            String username, String password) {
        final String defaultRoot = System.getProperty("attackframework.mappings.root", DEFAULT_MAPPINGS_RESOURCE_ROOT);
        final String resourceRoot = (mappingsResourceRoot == null || mappingsResourceRoot.isBlank())
                ? defaultRoot
                : mappingsResourceRoot;

        String mappingShortName = shortName == null ? "" : shortName.trim().toLowerCase(java.util.Locale.ROOT);
        final String mappingFile = resourceRoot + mappingShortName + ".json";

        Logger.logDebug("[OpenSearch] Attempting to create index: " + fullIndexName);
        Logger.logDebug("[OpenSearch] Using mapping file: " + mappingFile);

        String jsonBody = null;

        try {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl, username, password);

            boolean exists = client.indices().exists(b -> b.index(fullIndexName)).value();
            if (exists) {
                Logger.logDebug("[OpenSearch] Index already exists: " + fullIndexName);
                return new IndexResult(shortName, fullIndexName, IndexResult.Status.EXISTS, null);
            }

            try (InputStream is = OpenSearchSink.class.getResourceAsStream(mappingFile)) {
                if (is == null) {
                    String reason = "Mapping file not found: " + mappingFile;
                    Logger.logErrorPanelOnly("[OpenSearch] " + reason);
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
                Logger.logErrorPanelOnly("[OpenSearch] " + reason);
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

            Logger.logDebug("[OpenSearch] Create index " + fullIndexName + " acknowledged=" + response.acknowledged());

            return new IndexResult(
                    shortName,
                    fullIndexName,
                    response.acknowledged() ? IndexResult.Status.CREATED : IndexResult.Status.FAILED,
                    response.acknowledged() ? null : "Create not acknowledged"
            );

        } catch (IOException | RuntimeException e) {
            Logger.logErrorPanelOnly("[OpenSearch] Exception while creating index: " + fullIndexName);
            if (jsonBody != null) Logger.logErrorPanelOnly("[OpenSearch] Mapping JSON: " + compactJson(jsonBody));
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logErrorPanelOnly(sw.toString().stripTrailing());
            String reason = conciseRootCause(e);
            return new IndexResult(shortName, fullIndexName, IndexResult.Status.FAILED, reason);
        }
    }

    /**
     * Creates all indices required by the selected sources.
     *
     * <p>Only source keys recognized by {@link IndexNaming#computeIndexBaseNames(List)} produce
     * indices. For example, the Exporter index is created only when the {@code exporter} source is
     * selected.</p>
     */
    public static List<IndexResult> createSelectedIndexes(String baseUrl, List<String> selectedSources) {
        return createSelectedIndexes(baseUrl, selectedSources, null, null);
    }

    /**
     * Creates all indices required by the selected sources with optional basic auth.
     * When username and password are non-null and non-empty, uses basic auth.
     */
    public static List<IndexResult> createSelectedIndexes(String baseUrl, List<String> selectedSources,
            String username, String password) {
        return createSelectedIndexes(baseUrl, selectedSources, username, password, () -> true);
    }

    /**
     * Creates all indices required by the selected sources with optional basic auth.
     * Caller may provide a stop signal to cancel between index creations.
     */
    public static List<IndexResult> createSelectedIndexes(String baseUrl, List<String> selectedSources,
            String username, String password, BooleanSupplier shouldContinue) {
        Logger.logDebug("[OpenSearch] createSelectedIndexes sources=" + selectedSources);

        LinkedHashSet<String> shortNames = new LinkedHashSet<>(IndexNaming.computeSelectedIndexKeys(selectedSources));

        List<IndexResult> results = new ArrayList<>();
        for (String shortName : shortNames) {
            if (shouldContinue != null && !shouldContinue.getAsBoolean()) {
                break;
            }
            String displayName = IndexNaming.displayNameForIndexKey(shortName);
            Logger.logInfoPanelOnly("[OpenSearch] Creating index for " + displayName + ".");
            IndexResult result = createIndexFromResource(
                    baseUrl,
                    shortName,
                    RuntimeConfig.indexNameForKey(shortName),
                    null,
                    username,
                    password);
            Logger.logInfoPanelOnly("[OpenSearch] Index result for " + displayName + ": " + result.status() + ".");
            results.add(result);
        }
        return results;
    }

    /** Serializes mapping JSON to a single line so error logs do not clutter. */
    private static String compactJson(String json) {
        if (json == null || json.isBlank()) return json;
        try (JsonReader reader = Json.createReader(new StringReader(json));
             StringWriter sw = new StringWriter();
             JsonWriter writer = Json.createWriter(sw)) {
            writer.write(reader.read());
            return sw.toString();
        } catch (Exception e) {
            return json;
        }
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

    private static String resolvedFullIndexName(String shortName) {
        String normalized = shortName == null ? "" : shortName.trim().toLowerCase(java.util.Locale.ROOT);
        if (IndexNaming.indexKeys().contains(normalized)) {
            return RuntimeConfig.indexNameForKey(normalized);
        }
        return IndexNaming.normalizeBaseTemplate(RuntimeConfig.getState().indexNameBaseTemplate()) + "-" + normalized;
    }

}
