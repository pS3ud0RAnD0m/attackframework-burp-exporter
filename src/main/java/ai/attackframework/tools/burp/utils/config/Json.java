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
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * JSON marshaling for config import/export.
 * Produces compact JSON with deterministic field order (stable insertion order).
 */
public final class Json {

    static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(SerializationFeature.INDENT_OUTPUT, false); // compact output

    // Version is obtained strictly from the JAR manifest's Implementation-Version.
    private static final String VERSION = Version.get();

    // Common literals
    private static final String LIT_CUSTOM = "custom";
    private static final String LIT_REGEX  = "regex";
    private static final String LIT_STRING = "string";

    private Json() { }

    /** Dedicated runtime exception for config JSON errors. */
    public static final class ConfigJsonException extends RuntimeException {
        public ConfigJsonException(String message, Throwable cause) { super(message, cause); }
    }

    /**
     * Parsed config projection used by the UI and tests.
     * Null/empty defaulting behavior is handled via canonical constructor.
     */
    public record ImportedConfig(
            List<String> dataSources,
            String scopeType,
            List<String> scopeRegexes,
            List<String> scopeKinds,
            String filesPath,
            String openSearchUrl
    ) {
        public ImportedConfig {
            dataSources   = dataSources   == null ? List.of() : List.copyOf(dataSources);
            scopeType     = scopeType     == null ? "all"     : scopeType;
            scopeRegexes  = scopeRegexes  == null ? List.of() : List.copyOf(scopeRegexes);
            // scopeKinds may remain null
            // filesPath and openSearchUrl may remain null
        }
    }

    /* ======================== BUILD (from typed state) ======================== */

    // Package-private: only the typed mapper should call this.
    static String buildFromState(ConfigState.State state) {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", VERSION);

        buildDataSources(root, state);
        buildScope(root, state);
        buildSinks(root, state);

        try {
            return MAPPER.writeValueAsString(root);
        } catch (JsonProcessingException e) {
            throw new ConfigJsonException("JSON serialization error", e);
        }
    }

    private static void buildDataSources(ObjectNode root, ConfigState.State state) {
        ArrayNode srcArr = root.putArray("dataSources");
        for (String s : state.dataSources()) {
            if (s != null) srcArr.add(s);
        }
    }

    private static void buildScope(ObjectNode root, ConfigState.State state) {
        ObjectNode scope = root.putObject("scope");
        String scopeType = state.scopeType();
        if ("all".equals(scopeType)) {
            scope.put("all", true);
            return;
        }
        if ("burp".equals(scopeType)) {
            scope.put("burp", true);
            return;
        }
        // custom
        ObjectNode custom = scope.putObject(LIT_CUSTOM);
        int regexCount = 0;
        int stringCount = 0;

        for (ConfigState.ScopeEntry e : state.customEntries()) {
            // positive guard; no empty-body if, no continue
            if (e != null) {
                String value = e.value();
                if (value != null && !value.isBlank()) {
                    boolean isRegex = e.kind() != ConfigState.Kind.STRING;
                    if (isRegex) {
                        regexCount++;
                        custom.put(LIT_REGEX + regexCount, value);
                    } else {
                        stringCount++;
                        custom.put(LIT_STRING + stringCount, value);
                    }
                }
            }
        }
    }

    private static void buildSinks(ObjectNode root, ConfigState.State state) {
        var sinks = state.sinks();
        ObjectNode sinksNode = root.putObject("sinks");
        if (sinks == null) return;

        String files = sinks.filesPath();
        if (sinks.filesEnabled() && files != null && !files.isBlank()) {
            sinksNode.put("files", files);
        }
        String os = sinks.openSearchUrl();
        if (sinks.osEnabled() && os != null && !os.isBlank()) {
            sinksNode.put("openSearch", os);
        }
    }

    /* ======================== PARSE (into ImportedConfig) ===================== */

    public static ImportedConfig parseConfigJson(String json) throws IOException {
        JsonNode root = MAPPER.readTree(json);

        List<String> sources = parseDataSources(root);
        ScopeParts scope = parseScope(root);
        SinksParts sinks = parseSinks(root);

        return new ImportedConfig(
                sources,
                scope.type(),
                scope.values(),
                scope.kinds(),
                sinks.files(),
                sinks.os()
        );
    }

    /* ----------------------- parse helpers ----------------------- */

    private static List<String> parseDataSources(JsonNode root) {
        List<String> out = new ArrayList<>();
        JsonNode ds = root.path("dataSources");
        if (ds.isArray()) {
            for (JsonNode n : ds) {
                if (n.isTextual()) out.add(n.asText());
            }
        }
        return out;
    }

    private static ScopeParts parseScope(JsonNode root) {
        JsonNode scope = root.path("scope");

        if (scope.path("all").asBoolean(false)) {
            return new ScopeParts("all", List.of(), null);
        }
        if (scope.path("burp").asBoolean(false)) {
            return new ScopeParts("burp", List.of(), null);
        }

        JsonNode custom = scope.path(LIT_CUSTOM);
        if (custom.isObject()) {
            return parseCustomObject(custom);
        } else if (custom.isArray()) {
            return parseCustomArray(scope, custom);
        }
        // default to custom with no entries
        return new ScopeParts(LIT_CUSTOM, List.of(), null);
    }

    private static ScopeParts parseCustomObject(JsonNode custom) {
        List<String> vals = new ArrayList<>();
        List<String> kindsList = new ArrayList<>();
        for (Iterator<Map.Entry<String, JsonNode>> it = custom.fields(); it.hasNext();) {
            Map.Entry<String, JsonNode> e = it.next();
            JsonNode v = e.getValue();
            if (!v.isTextual()) {
                continue;
            }
            String key = e.getKey();
            // stringX => string, everything else => regex
            String kind = key.startsWith(LIT_STRING) ? LIT_STRING : LIT_REGEX;
            kindsList.add(kind);
            vals.add(v.asText());
        }
        return new ScopeParts(LIT_CUSTOM, vals, kindsList);
    }

    private static ScopeParts parseCustomArray(JsonNode scope, JsonNode custom) {
        List<String> vals = new ArrayList<>();
        for (JsonNode n : custom) {
            if (n.isTextual()) vals.add(n.asText());
        }

        List<String> kindsList = null;
        JsonNode types = scope.path("customTypes");
        if (types.isArray() && types.size() == vals.size()) {
            kindsList = new ArrayList<>(types.size());
            for (JsonNode t : types) {
                kindsList.add(t.isTextual() ? t.asText() : LIT_REGEX);
            }
        }
        return new ScopeParts(LIT_CUSTOM, vals, kindsList);
    }

    private static SinksParts parseSinks(JsonNode root) {
        JsonNode sinks = root.path("sinks");

        String files = null;
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

        return new SinksParts(files, os);
    }

    /* ----------------------- small carrier records ----------------------- */

    private record ScopeParts(String type, List<String> values, List<String> kinds) { }
    private record SinksParts(String files, String os) { }
}
