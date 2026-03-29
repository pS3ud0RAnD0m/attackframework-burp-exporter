package ai.attackframework.tools.burp.utils.config;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Typed configuration model for import/export and UI binding.
 * Immutable records with defensive copying where lists are provided.
 */
public final class ConfigState {

    /** Default settings sub-options (project, user). */
    public static final List<String> DEFAULT_SETTINGS_SUB =
            List.of(ConfigKeys.SRC_SETTINGS_PROJECT, ConfigKeys.SRC_SETTINGS_USER);

    /** Default traffic tool types: empty (no traffic exported by default). */
    public static final List<String> DEFAULT_TRAFFIC_TOOL_TYPES = List.of();

    /** Legacy default for traffic when parsing config without dataSourceOptions (PROXY, REPEATER). */
    public static final List<String> LEGACY_TRAFFIC_TOOL_TYPES = List.of("PROXY", "REPEATER");

    /** Default findings severities: all five. */
    public static final List<String> DEFAULT_FINDINGS_SEVERITIES =
            List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL");

    /** Default total cap across exporter files under the selected root. */
    public static final long DEFAULT_FILE_TOTAL_CAP_BYTES = 5L * 1024L * 1024L * 1024L;

    /** Default advanced disk-used threshold for file export. */
    public static final int DEFAULT_FILE_MAX_DISK_USED_PERCENT = 95;

    /** Verify OpenSearch TLS certificates against the system trust store. */
    public static final String OPEN_SEARCH_TLS_VERIFY = "verify";
    /** Trust only the session-imported pinned OpenSearch certificate. */
    public static final String OPEN_SEARCH_TLS_PINNED = "pinned";
    /** Trust all OpenSearch TLS certificates without verification. */
    public static final String OPEN_SEARCH_TLS_INSECURE = "insecure";

    /** Scope kind for {@link ScopeEntry}. */
    public enum Kind { REGEX, STRING }

    /** Ordered custom-scope entry. */
    public record ScopeEntry(String value, Kind kind) {
        public ScopeEntry {
            value = value == null ? "" : value;
            kind  = kind == null ? Kind.REGEX : kind;
        }
    }

    /**
     * Sinks selection and values.
     *
     * <p>File export can target document-only JSONL, bulk-compatible NDJSON, or both. Optional
     * OpenSearch basic-auth remains non-durable (empty = no auth). {@code openSearchTlsMode}
     * persists whether OpenSearch uses the system trust store, a session-imported pinned
     * certificate, or trust-all TLS.</p>
     */
    public record Sinks(boolean filesEnabled, String filesPath, boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                        boolean fileTotalCapEnabled, long fileTotalCapBytes,
                        boolean fileDiskUsagePercentEnabled, int fileDiskUsagePercent,
                        boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword, String openSearchTlsMode) {
        public Sinks {
            filesPath = filesPath != null ? filesPath : "";
            fileTotalCapBytes = fileTotalCapBytes > 0 ? fileTotalCapBytes : DEFAULT_FILE_TOTAL_CAP_BYTES;
            fileDiskUsagePercent = Math.clamp(fileDiskUsagePercent, 1, 100);
            openSearchUser = openSearchUser != null ? openSearchUser : "";
            openSearchPassword = openSearchPassword != null ? openSearchPassword : "";
            openSearchTlsMode = normalizeOpenSearchTlsMode(openSearchTlsMode);
        }

        public Sinks(boolean filesEnabled, String filesPath,
                     boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     String openSearchTlsMode) {
            this(filesEnabled, filesPath, fileJsonlEnabled, fileBulkNdjsonEnabled,
                    true, DEFAULT_FILE_TOTAL_CAP_BYTES,
                    true, DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword, openSearchTlsMode);
        }

        public Sinks(boolean filesEnabled, String filesPath, boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                     boolean fileTotalCapEnabled, long fileTotalCapBytes,
                     boolean fileDiskUsagePercentEnabled, int fileDiskUsagePercent,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     boolean openSearchInsecureSsl) {
            this(filesEnabled, filesPath, fileJsonlEnabled, fileBulkNdjsonEnabled,
                    fileTotalCapEnabled, fileTotalCapBytes,
                    fileDiskUsagePercentEnabled, fileDiskUsagePercent,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword,
                    openSearchInsecureSsl ? OPEN_SEARCH_TLS_INSECURE : OPEN_SEARCH_TLS_VERIFY);
        }

        public Sinks(boolean filesEnabled, String filesPath,
                     boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     boolean openSearchInsecureSsl) {
            this(filesEnabled, filesPath, fileJsonlEnabled, fileBulkNdjsonEnabled,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword,
                    openSearchInsecureSsl ? OPEN_SEARCH_TLS_INSECURE : OPEN_SEARCH_TLS_VERIFY);
        }

        /**
         * Backward-compatible constructor for older call sites that predate explicit file formats.
         *
         * <p>When used, file export formats default to disabled until explicitly selected in the
         * UI or config.</p>
         */
        public Sinks(boolean filesEnabled, String filesPath,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     String openSearchTlsMode) {
            this(filesEnabled, filesPath, false, false,
                    true, DEFAULT_FILE_TOTAL_CAP_BYTES,
                    true, DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword, openSearchTlsMode);
        }

        public Sinks(boolean filesEnabled, String filesPath,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     boolean openSearchInsecureSsl) {
            this(filesEnabled, filesPath, osEnabled, openSearchUrl, openSearchUser, openSearchPassword,
                    openSearchInsecureSsl ? OPEN_SEARCH_TLS_INSECURE : OPEN_SEARCH_TLS_VERIFY);
        }
    }

    /** Top-level state. */
    public record State(List<String> dataSources,
                        String scopeType,               // "all" | "burp" | "custom"
                        List<ScopeEntry> customEntries, // ordered; used when scopeType=custom
                        Sinks sinks,
                        List<String> settingsSub,       // "project", "user"; default both
                        List<String> trafficToolTypes,  // ToolType names; default empty (no traffic)
                        List<String> findingsSeverities, // AuditIssueSeverity names; default all five
                        Map<String, Set<String>> enabledExportFieldsByIndex) { // index shortName -> enabled toggleable field keys; null = all enabled

        public State {
            dataSources       = dataSources == null ? List.of() : List.copyOf(dataSources);
            scopeType         = scopeType == null ? "all" : scopeType;
            customEntries     = customEntries == null ? List.of() : List.copyOf(customEntries);
            settingsSub       = settingsSub == null ? List.of() : List.copyOf(settingsSub);
            trafficToolTypes  = trafficToolTypes == null ? List.of() : List.copyOf(trafficToolTypes);
            findingsSeverities = findingsSeverities == null ? List.of() : List.copyOf(findingsSeverities);
            enabledExportFieldsByIndex = enabledExportFieldsByIndex == null ? null : copyMapOfSets(enabledExportFieldsByIndex);
        }

        private static Map<String, Set<String>> copyMapOfSets(Map<String, Set<String>> map) {
            Map<String, Set<String>> out = new java.util.LinkedHashMap<>();
            for (Map.Entry<String, Set<String>> e : map.entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    out.put(e.getKey(), Collections.unmodifiableSet(new java.util.LinkedHashSet<>(e.getValue())));
                }
            }
            return Collections.unmodifiableMap(out);
        }
    }

    private ConfigState() { }

    /** Returns a normalized persisted OpenSearch TLS mode, defaulting to {@link #OPEN_SEARCH_TLS_VERIFY}. */
    public static String normalizeOpenSearchTlsMode(String mode) {
        if (mode == null || mode.isBlank()) {
            return OPEN_SEARCH_TLS_VERIFY;
        }
        return switch (mode.trim().toLowerCase(java.util.Locale.ROOT)) {
            case OPEN_SEARCH_TLS_PINNED, "trust pinned certificate", "trust-pinned-certificate" -> OPEN_SEARCH_TLS_PINNED;
            case OPEN_SEARCH_TLS_INSECURE, "trust all certificates", "trust-all-certificates" -> OPEN_SEARCH_TLS_INSECURE;
            default -> OPEN_SEARCH_TLS_VERIFY;
        };
    }
}
