package ai.attackframework.tools.burp.utils.config;

import ai.attackframework.tools.burp.utils.Version;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * JSON marshaling for ConfigPanel import/export.
 * Produces compact JSON with deterministic field order (stable insertion order).
 */
public final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(SerializationFeature.INDENT_OUTPUT, false); // compact output

    // Version is obtained strictly from the JAR manifest's Implementation-Version.
    private static final String VERSION = Version.get();

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
     * Output shape:
     * {
     *   "version": "1.2.3",
     *   "dataSources": [...],
     *   "scope": {
     *     "custom": {
     *       "regex1": "...",
     *       "regex2": "...",
     *       "string1": "...",
     *       "string2": "..."
     *     }
     *   },
     *   "sinks": { ... }
     * }
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

        // Put version first so it appears at the top.
        root.put("version", VERSION);

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
            ObjectNode custom = scope.putObject("custom");

            if (scopeValues != null && !scopeValues.isEmpty()) {
                int regexCount = 0;
                int stringCount = 0;

                boolean typed = scopeKinds != null && scopeKinds.size() == scopeValues.size();

                for (int i = 0; i < scopeValues.size(); i++) {
                    String value = scopeValues.get(i);
                    if (value == null) continue;

                    String kind = typed ? scopeKinds.get(i) : "regex";
                    boolean isRegex = "regex".equalsIgnoreCase(kind);

                    if (isRegex) {
                        regexCount++;
                        custom.put("regex" + regexCount, value);
                    } else {
                        stringCount++;
                        custom.put("string" + stringCount, value);
                    }
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

    /**
     * Parser that accepts:
     *  - New typed-object shape: {"custom": {"regex1": "...", "string1": "..."}}
     *  - Legacy array: {"custom": ["...", "..."]}
     *  - Typed arrays with "customTypes"
     *
     * Relies on the ObjectNode insertion order to preserve the sequence
     * of entries as they originally appeared in the JSON document.
     */
    public static ImportedConfig parseConfigJson(String json) throws IOException {
        JsonNode root = MAPPER.readTree(json);

        // dataSources
        List<String> sources = new ArrayList<>();
        JsonNode ds = root.path("dataSources");
        if (ds.isArray()) {
            for (JsonNode n : ds) {
                if (n.isTextual()) sources.add(n.asText());
            }
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

            if (custom.isObject()) {
                // Iterate in insertion order (ObjectNode preserves order using LinkedHashMap)
                List<String> kindsList = new ArrayList<>();
                for (Iterator<Map.Entry<String, JsonNode>> it = custom.fields(); it.hasNext();) {
                    Map.Entry<String, JsonNode> e = it.next();
                    JsonNode v = e.getValue();
                    if (v.isTextual()) {
                        String key = e.getKey();
                        String kind;
                        if (key.startsWith("string")) {
                            kind = "string";
                        } else if (key.startsWith("regex")) {
                            kind = "regex";
                        } else {
                            kind = "regex"; // default
                        }
                        kindsList.add(kind);
                        scopeVals.add(v.asText());
                    }
                }
                scopeKinds = kindsList;
            } else if (custom.isArray()) {
                // Legacy support
                for (JsonNode n : custom) {
                    if (n.isTextual()) scopeVals.add(n.asText());
                }

                JsonNode kinds = scope.path("customTypes");
                if (kinds.isArray() && kinds.size() == scopeVals.size()) {
                    List<String> kindsList = new ArrayList<>();
                    for (JsonNode k : kinds) {
                        kindsList.add(k.isTextual() ? k.asText() : "regex");
                    }
                    scopeKinds = kindsList;
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
