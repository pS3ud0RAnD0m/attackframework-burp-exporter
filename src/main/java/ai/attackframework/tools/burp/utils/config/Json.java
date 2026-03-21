package ai.attackframework.tools.burp.utils.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ai.attackframework.tools.burp.utils.Version;

/**
 * JSON marshaling for config import/export.
 * Produces pretty JSON with deterministic field order (stable insertion order).
 */
public final class Json {

    static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(SerializationFeature.INDENT_OUTPUT, true);

    // Version is obtained strictly from the JAR manifest's Implementation-Version.
    private static final String VERSION = Version.get();

    // Common literals
    private static final String LIT_SCOPE  = "scope";
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
     * Null/empty defaulting behavior is handled via the constructor.
     */
    @SuppressWarnings("java:S6206") // Sonar: this could be a record; keep as class for explicit defensive copying and SpotBugs-friendly structure
    public static final class ImportedConfig {

        private final List<String> dataSources;
        private final String scopeType;
        private final List<String> scopeRegexes;
        private final List<String> scopeKinds;
        private final String filesPath;
        private final String openSearchUrl;
        private final String openSearchUser;
        private final String openSearchPassword;
        private final boolean openSearchInsecureSsl;
        private final List<String> settingsSub;
        private final List<String> trafficToolTypes;
        private final List<String> findingsSeverities;
        private final Map<String, Set<String>> enabledExportFieldsByIndex;

        public ImportedConfig(
                List<String> dataSources,
                String scopeType,
                List<String> scopeRegexes,
                List<String> scopeKinds,
                String filesPath,
                String openSearchUrl,
                String openSearchUser,
                String openSearchPassword,
                boolean openSearchInsecureSsl,
                List<String> settingsSub,
                List<String> trafficToolTypes,
                List<String> findingsSeverities,
                Map<String, Set<String>> enabledExportFieldsByIndex
        ) {
            this.dataSources = dataSources == null ? List.of() : List.copyOf(dataSources);
            this.scopeType = scopeType == null ? "all" : scopeType;
            this.scopeRegexes = scopeRegexes == null ? List.of() : List.copyOf(scopeRegexes);
            this.scopeKinds = scopeKinds == null ? null : List.copyOf(scopeKinds);
            this.filesPath = filesPath;
            this.openSearchUrl = openSearchUrl;
            this.openSearchUser = openSearchUser != null ? openSearchUser : "";
            this.openSearchPassword = openSearchPassword != null ? openSearchPassword : "";
            this.openSearchInsecureSsl = openSearchInsecureSsl;
            this.settingsSub = settingsSub == null ? List.of() : List.copyOf(settingsSub);
            this.trafficToolTypes = trafficToolTypes == null ? List.of() : List.copyOf(trafficToolTypes);
            this.findingsSeverities = findingsSeverities == null ? List.of() : List.copyOf(findingsSeverities);
            this.enabledExportFieldsByIndex = copyMapOfSets(enabledExportFieldsByIndex);
        }

        private static Map<String, Set<String>> copyMapOfSets(Map<String, Set<String>> map) {
            if (map == null || map.isEmpty()) return null;
            Map<String, Set<String>> out = new java.util.LinkedHashMap<>();
            for (Map.Entry<String, Set<String>> e : map.entrySet()) {
                if (e.getKey() != null && e.getValue() != null && !e.getValue().isEmpty()) {
                    out.put(e.getKey(), Collections.unmodifiableSet(new LinkedHashSet<>(e.getValue())));
                }
            }
            return out.isEmpty() ? null : Collections.unmodifiableMap(out);
        }

        public List<String> dataSources() {
            return dataSources;
        }

        public String scopeType() {
            return scopeType;
        }

        public List<String> scopeRegexes() {
            return scopeRegexes;
        }

        public List<String> scopeKinds() {
            return scopeKinds;
        }

        public String filesPath() {
            return filesPath;
        }

        public String openSearchUrl() {
            return openSearchUrl;
        }

        public String openSearchUser() {
            return openSearchUser;
        }

        public String openSearchPassword() {
            return openSearchPassword;
        }

        public boolean openSearchInsecureSsl() {
            return openSearchInsecureSsl;
        }

        public List<String> settingsSub() {
            return settingsSub;
        }

        public List<String> trafficToolTypes() {
            return trafficToolTypes;
        }

        public List<String> findingsSeverities() {
            return findingsSeverities;
        }

        /** Null when absent or empty (all fields enabled). */
        public Map<String, Set<String>> enabledExportFieldsByIndex() {
            return enabledExportFieldsByIndex;
        }
    }

    /* ======================== BUILD (from typed state) ======================== */

    // Package-private: only the typed mapper should call this.
    static String buildFromState(ConfigState.State state) {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", VERSION);

        buildDataSources(root, state);
        buildDataSourceOptions(root, state);
        buildScope(root, state);
        buildSinks(root, state);
        buildExportFields(root, state);

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

    private static void buildDataSourceOptions(ObjectNode root, ConfigState.State state) {
        ObjectNode opts = root.putObject("dataSourceOptions");
        ArrayNode settingsArr = opts.putArray("settings");
        if (state.settingsSub() != null) {
            for (String s : state.settingsSub()) {
                if (s != null) settingsArr.add(s);
            }
        }
        ArrayNode trafficArr = opts.putArray("traffic");
        if (state.trafficToolTypes() != null) {
            for (String s : state.trafficToolTypes()) {
                if (s != null) trafficArr.add(s);
            }
        }
        ArrayNode findingsArr = opts.putArray("findings");
        if (state.findingsSeverities() != null) {
            for (String s : state.findingsSeverities()) {
                if (s != null) findingsArr.add(s);
            }
        }
    }

    private static void buildScope(ObjectNode root, ConfigState.State state) {
        String scopeType = state.scopeType();

        // Simple radio scopes ("all", "burp") are represented as an array of strings, e.g.:
        //   "scope": ["all"]
        //   "scope": ["burp"]
        if ("all".equals(scopeType) || "burp".equals(scopeType)) {
            ArrayNode scopeArr = root.putArray(LIT_SCOPE);
            scopeArr.add(scopeType);
            return;
        }

        // Custom scope keeps object form for its entries, e.g.:
        //   "scope": { "custom": { "regex1": "^example$", "string1": "foo" } }
        ObjectNode scope = root.putObject(LIT_SCOPE);
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
        if (sinks.openSearchInsecureSsl()) sinksNode.put("openSearchInsecureSsl", true);
    }

    private static void buildExportFields(ObjectNode root, ConfigState.State state) {
        Map<String, Set<String>> byIndex = state.enabledExportFieldsByIndex();
        if (byIndex == null || byIndex.isEmpty()) return;
        ObjectNode exportFields = root.putObject("exportFields");
        for (Map.Entry<String, Set<String>> e : byIndex.entrySet()) {
            if (e.getKey() == null || e.getValue() == null) continue;
            ArrayNode arr = exportFields.putArray(e.getKey());
            for (String field : e.getValue()) {
                if (field != null) arr.add(field);
            }
        }
    }

    /* ======================== PARSE (into ImportedConfig) ===================== */

    public static ImportedConfig parseConfigJson(String json) throws IOException {
        JsonNode root = MAPPER.readTree(json);

        List<String> sources = parseDataSources(root);
        DataSourceOptionsParts opts = parseDataSourceOptions(root);
        ScopeParts scope = parseScope(root);
        SinksParts sinks = parseSinks(root);
        Map<String, Set<String>> exportFields = parseExportFields(root);

        return new ImportedConfig(
                sources,
                scope.type(),
                scope.values(),
                scope.kinds(),
                sinks.files(),
                sinks.os(),
                sinks.osUser(),
                sinks.osPass(),
                sinks.openSearchInsecureSsl(),
                opts.settingsSub(),
                opts.trafficToolTypes(),
                opts.findingsSeverities(),
                exportFields
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

    /**
     * Parses dataSourceOptions. If absent (legacy config), returns defaults:
     * settings both, traffic PROXY+REPEATER (legacy), findings all severities.
     */
    private static DataSourceOptionsParts parseDataSourceOptions(JsonNode root) {
        JsonNode opts = root.path("dataSourceOptions");
        if (!opts.isObject()) {
            return new DataSourceOptionsParts(
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.LEGACY_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES
            );
        }
        List<String> settings = arrayToStringList(opts.path("settings"));
        List<String> traffic = arrayToStringList(opts.path("traffic"));
        List<String> findings = arrayToStringList(opts.path("findings"));
        return new DataSourceOptionsParts(
                settings.isEmpty() ? ConfigState.DEFAULT_SETTINGS_SUB : settings,
                traffic,
                findings.isEmpty() ? ConfigState.DEFAULT_FINDINGS_SEVERITIES : findings
        );
    }

    private static List<String> arrayToStringList(JsonNode arr) {
        List<String> out = new ArrayList<>();
        if (arr.isArray()) {
            for (JsonNode n : arr) {
                if (n.isTextual()) out.add(n.asText());
            }
        }
        return out;
    }

    private static ScopeParts parseScope(JsonNode root) {
        JsonNode scope = root.path(LIT_SCOPE);

        // New representation: simple scopes as array of strings, e.g. ["all"] or ["burp"].
        if (scope.isArray() && !scope.isEmpty()) {
            JsonNode first = scope.get(0);
            if (first.isTextual()) {
                String v = first.asText();
                if ("all".equals(v) || "burp".equals(v)) {
                    return new ScopeParts(v, List.of(), null);
                }
            }
            // Empty / unrecognized array: fall through to legacy/custom handling below.
        }

        // Legacy representation: object with boolean flags ("all": true / "burp": true).
        if (scope.path("all").asBoolean(false)) {
            return new ScopeParts("all", List.of(), null);
        }
        if (scope.path("burp").asBoolean(false)) {
            return new ScopeParts("burp", List.of(), null);
        }

        // Custom scope: either object or array (plus optional customTypes), as before.
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
        for (Iterator<String> it = custom.fieldNames(); it.hasNext(); ) {
            String key = it.next();
            JsonNode v = custom.get(key);
            if (!v.isTextual()) {
                continue;
            }
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

        boolean insecureSsl = sinks.path("openSearchInsecureSsl").asBoolean(false);

        return new SinksParts(files, os, "", "", insecureSsl);
    }

    /** Returns null when absent or empty (all fields enabled). */
    private static Map<String, Set<String>> parseExportFields(JsonNode root) {
        JsonNode exportFields = root.path("exportFields");
        if (!exportFields.isObject()) return null;
        Map<String, Set<String>> out = new java.util.LinkedHashMap<>();
        for (Iterator<String> it = exportFields.fieldNames(); it.hasNext(); ) {
            String indexName = it.next();
            JsonNode arr = exportFields.get(indexName);
            if (!arr.isArray()) continue;
            Set<String> set = new LinkedHashSet<>();
            for (JsonNode n : arr) {
                if (n.isTextual()) set.add(n.asText());
            }
            if (!set.isEmpty()) out.put(indexName, Set.copyOf(set));
        }
        return out.isEmpty() ? null : Map.copyOf(out);
    }

    /* ----------------------- small carrier records ----------------------- */

    private record ScopeParts(String type, List<String> values, List<String> kinds) { }
    private record SinksParts(String files, String os, String osUser, String osPass, boolean openSearchInsecureSsl) { }
    private record DataSourceOptionsParts(List<String> settingsSub, List<String> trafficToolTypes, List<String> findingsSeverities) { }
}
