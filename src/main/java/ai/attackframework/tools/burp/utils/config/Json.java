package ai.attackframework.tools.burp.utils.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON helpers for exporting/importing the ConfigPanel state.
 * Switched to Jackson for robust serialization/parsing to avoid fragile custom escaping.
 * Public surface is kept identical so callers (e.g., ConfigPanel) need no changes.
 */
public final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private Json() {}

    /** Container representing the parsed config snapshot. */
    public static final class ImportedConfig {
        public final List<String> dataSources = new ArrayList<>();
        public String scopeType = "all";              // "custom" | "burp" | "all"
        public final List<String> scopeRegexes = new ArrayList<>();
        public String filesPath;                      // nullable
        public String openSearchUrl;                  // nullable
    }

    /** Builds a pretty-printed JSON snapshot of current config (non-secret settings only). */
    public static String buildPrettyConfigJson(
            List<String> sources,
            String scopeType,               // "burp" | "custom" | "all"
            List<String> scopeRegexes,      // only when custom; may be empty
            boolean filesEnabled,
            String filesRoot,
            boolean openSearchEnabled,
            String openSearchUrl) {

        Map<String, Object> root = new LinkedHashMap<>();

        // dataSources
        root.put("dataSources", sources == null ? List.of() : sources);

        // scope
        Map<String, Object> scope = new LinkedHashMap<>();
        if ("custom".equals(scopeType)) {
            scope.put("custom", scopeRegexes == null ? List.of() : scopeRegexes);
        } else if ("burp".equals(scopeType)) {
            scope.put("burp", List.of());
        } else {
            scope.put("all", List.of());
        }
        root.put("scope", scope);

        // sinks
        Map<String, Object> sinks = new LinkedHashMap<>();
        if (filesEnabled) {
            sinks.put("files", filesRoot == null ? "" : filesRoot);
        }
        if (openSearchEnabled) {
            sinks.put("openSearch", openSearchUrl == null ? "" : openSearchUrl);
        }
        root.put("sinks", sinks);

        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (JsonProcessingException e) {
            return "{ \"dataSources\": [], \"scope\": { \"all\": [] }, \"sinks\": {} }";
        }
    }

    /**
     * Parses the JSON produced by {@link #buildPrettyConfigJson}.
     * Uses Jackson for tolerant parsing.
     */
    public static ImportedConfig parseConfigJson(String json) {
        ImportedConfig cfg = new ImportedConfig();
        if (json == null || json.isEmpty()) return cfg;
        try {
            JsonNode root = MAPPER.readTree(json);

            // dataSources
            JsonNode ds = root.path("dataSources");
            if (ds.isArray()) {
                for (JsonNode n : ds) if (n.isTextual()) cfg.dataSources.add(n.asText());
            }

            // scope
            JsonNode scope = root.path("scope");
            if (scope.isObject()) {
                if (scope.has("custom")) {
                    cfg.scopeType = "custom";
                    JsonNode arr = scope.path("custom");
                    if (arr.isArray()) {
                        for (JsonNode n : arr) if (n.isTextual()) cfg.scopeRegexes.add(n.asText());
                    }
                } else if (scope.has("burp")) {
                    cfg.scopeType = "burp";
                } else {
                    cfg.scopeType = "all";
                }
            }

            // sinks
            JsonNode sinks = root.path("sinks");
            if (sinks.isObject()) {
                if (sinks.has("files") && !sinks.path("files").isNull()) {
                    String val = sinks.path("files").asText();
                    cfg.filesPath = (val != null && !val.isEmpty()) ? val : null;
                }
                if (sinks.has("openSearch") && !sinks.path("openSearch").isNull()) {
                    String val = sinks.path("openSearch").asText();
                    cfg.openSearchUrl = (val != null && !val.isEmpty()) ? val : null;
                }
            }
        } catch (Exception ignore) {
            // Leave defaults if parsing fails
        }
        return cfg;
    }

    // ---- legacy helpers retained for compatibility; delegate to Jackson ----

    /** @deprecated Prefer treating JSON as data via write/read methods. */
    @Deprecated
    static String jsonEscape(String s) {
        if (s == null) return "";
        try {
            String quoted = MAPPER.writeValueAsString(s);
            int n = quoted.length();
            if (n >= 2 && quoted.charAt(0) == '\"' && quoted.charAt(n - 1) == '\"') {
                return quoted.substring(1, n - 1);
            }
            return quoted;
        } catch (Exception e) {
            return s;
        }
    }

    /** @deprecated Prefer treating JSON as data via write/read methods. */
    @Deprecated
    static String jsonUnescape(String s) {
        if (s == null) return null;
        try {
            return MAPPER.readValue('"' + s + '"', String.class);
        } catch (Exception e) {
            return s;
        }
    }
}
