package ai.attackframework.tools.burp.utils.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * JSON marshaling for ConfigPanel import/export.
 * Produces compact JSON with deterministic field order
 * (stable insertion order plus map-entry sorting).
 */
public final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            // Keep map keys ordered to ensure stable output across JVMs.
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            // Compact output (pretty printing not required).
            .configure(SerializationFeature.INDENT_OUTPUT, false);

    private Json() { }

    /** Parsed config projection used by the UI. */
    public static final class ImportedConfig {
        public final List<String> dataSources;
        public final String scopeType;          // "all", "burp", or "custom"
        public final List<String> scopeRegexes; // For "custom": values as entered
        public final List<String> scopeKinds;   // Optional: "regex" or "string" per entry (can be null)
        public final String filesPath;          // Null if disabled or empty
        public final String openSearchUrl;      // Null if disabled or empty

        public ImportedConfig(List<String> dataSources,
                              String scopeType,
                              List<String> scopeRegexes,
                              List<String> scopeKinds,
                              String filesPath,
                              String openSearchUrl) {
            this.dataSources = dataSources != null ? dataSources : Collections.emptyList();
            this.scopeType = scopeType != null ? scopeType : "all";
            this.scopeRegexes = scopeRegexes != null ? scopeRegexes : Collections.emptyList();
            this.scopeKinds = scopeKinds;
            this.filesPath = filesPath;
            this.openSearchUrl = openSearchUrl;
        }
    }

    /**
     * Backward-compatibility builder matching the previous untyped shape.
     * For a "custom" scope, entries are assumed to be regex.
     */
    @SuppressWarnings("unused")
    public static String buildPrettyConfigJson(List<String> sources,
                                               String scopeType,
                                               List<String> scopeValues,
                                               boolean filesEnabled,
                                               String filesRoot,
                                               boolean osEnabled,
                                               String osUrl) {
        List<String> kinds = null;
        if ("custom".equals(scopeType) && scopeValues != null) {
            kinds = new ArrayList<>();
            for (int i = 0; i < scopeValues.size(); i++) {
                kinds.add("regex");
            }
        }
        return buildConfigJsonTyped(sources, scopeType, scopeValues, kinds, filesEnabled, filesRoot, osEnabled, osUrl);
    }

    /**
     * Builder with per-entry kinds for the custom scope.
     * Output keeps legacy {@code "scope.custom":[...]} and adds {@code "scope.customTypes":[...]}.
     */
    public static String buildConfigJsonTyped(List<String> sources,
                                              String scopeType,
                                              List<String> scopeValues,
                                              List<String> scopeKinds,
                                              boolean filesEnabled,
                                              String filesRoot,
                                              boolean osEnabled,
                                              String osUrl) {

        ObjectNode root = MAPPER.createObjectNode();

        // dataSources
        ArrayNode srcArr = root.putArray("dataSources");
        if (sources != null) {
            for (String s : sources) {
                if (s != null) srcArr.add(s);
            }
        }

        // scope
        ObjectNode scope = root.putObject("scope");
        if ("all".equals(scopeType)) {
            scope.put("all", true);
        } else if ("burp".equals(scopeType)) {
            scope.put("burp", true);
        } else { // "custom"
            ArrayNode vals = scope.putArray("custom");
            if (scopeValues != null) {
                for (String v : scopeValues) {
                    if (v != null) vals.add(v);
                }
            }
            if (scopeKinds != null && scopeValues != null && scopeKinds.size() == scopeValues.size()) {
                ArrayNode kinds = scope.putArray("customTypes");
                for (String k : scopeKinds) {
                    kinds.add(k);
                }
            }
        }

        // sinks
        ObjectNode sinks = root.putObject("sinks");
        if (filesEnabled && filesRoot != null && !filesRoot.isBlank()) {
            sinks.put("files", filesRoot);
        }
        if (osEnabled && osUrl != null && !osUrl.isBlank()) {
            sinks.put("openSearch", osUrl);
        }

        try {
            return MAPPER.writeValueAsString(root);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON serialization error", e);
        }
    }

    /** Lenient parser that accepts both legacy and typed custom-scope shapes. */
    public static ImportedConfig parseConfigJson(String json) throws IOException {
        JsonNode root = MAPPER.readTree(json);

        // dataSources
        List<String> sources = new ArrayList<>();
        JsonNode ds = root.path("dataSources");
        if (ds.isArray()) {
            for (JsonNode n : ds) if (n.isTextual()) sources.add(n.asText());
        }

        // scope
        String scopeType;
        List<String> scopeVals = new ArrayList<>();
        List<String> scopeKinds = null;

        JsonNode scope = root.path("scope");
        if (scope.path("all").asBoolean(false)) {
            scopeType = "all";
        } else if (scope.path("burp").asBoolean(false)) {
            scopeType = "burp";
        } else {
            scopeType = "custom";
            JsonNode custom = scope.path("custom");
            if (custom.isArray()) {
                for (JsonNode n : custom) if (n.isTextual()) scopeVals.add(n.asText());
            }
            JsonNode kinds = scope.path("customTypes");
            if (kinds.isArray() && kinds.size() == scopeVals.size()) {
                scopeKinds = new ArrayList<>();
                for (JsonNode k : kinds) {
                    scopeKinds.add(k.isTextual() ? k.asText() : "regex");
                }
            }
        }

        // sinks
        String files = null;
        JsonNode sinks = root.path("sinks");
        JsonNode filesNode = sinks.path("files");
        if (filesNode.isTextual()) {
            String v = filesNode.asText();
            if (!v.isBlank()) files = v;
        }
        String os = null;
        JsonNode osNode = sinks.path("openSearch");
        if (osNode.isTextual()) {
            String v = osNode.asText();
            if (!v.isBlank()) os = v;
        }

        return new ImportedConfig(sources, scopeType, scopeVals, scopeKinds, files, os);
    }
}
