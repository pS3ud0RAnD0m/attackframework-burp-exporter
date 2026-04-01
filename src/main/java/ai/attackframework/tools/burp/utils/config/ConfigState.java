package ai.attackframework.tools.burp.utils.config;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
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

    /** Default findings severities: all five. */
    public static final List<String> DEFAULT_FINDINGS_SEVERITIES =
            List.of("critical", "high", "medium", "low", "informational");

    /** Default total cap across exporter files under the selected root, stored as human-friendly GB. */
    public static final double DEFAULT_FILE_TOTAL_CAP_GB = 5d;

    /** Default advanced disk-used threshold for file export. */
    public static final int DEFAULT_FILE_MAX_DISK_USED_PERCENT = 95;
    /** Default Stats panel chart style (1 = Smooth). */
    public static final int DEFAULT_STATS_CHART_STYLE = 1;
    /** Default minimum visible level in LogPanel. */
    public static final String DEFAULT_LOG_MIN_LEVEL = "trace";

    /** Verify OpenSearch TLS certificates against the system trust store. */
    public static final String OPEN_SEARCH_TLS_VERIFY = "verify";
    /** Trust only the session-imported pinned OpenSearch certificate. */
    public static final String OPEN_SEARCH_TLS_PINNED = "pinned";
    /** Trust all OpenSearch TLS certificates without verification. */
    public static final String OPEN_SEARCH_TLS_INSECURE = "insecure";

    /** Scope kind for {@link ScopeEntry}. */
    public enum Kind { REGEX, STRING }

    private static final BigDecimal GB_BYTES_DECIMAL = BigDecimal.valueOf(1024L * 1024L * 1024L);
    private static final BigDecimal LONG_MAX_DECIMAL = BigDecimal.valueOf(Long.MAX_VALUE);

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
                        boolean fileTotalCapEnabled, double fileTotalCapGb,
                        boolean fileDiskUsagePercentEnabled, int fileDiskUsagePercent,
                        boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword, String openSearchTlsMode) {
        public Sinks {
            filesPath = filesPath != null ? filesPath : "";
            fileTotalCapGb = normalizeFileTotalCapGb(fileTotalCapGb);
            fileDiskUsagePercent = Math.clamp(fileDiskUsagePercent, 1, 100);
            openSearchUser = openSearchUser != null ? openSearchUser : "";
            openSearchPassword = openSearchPassword != null ? openSearchPassword : "";
            openSearchTlsMode = normalizeOpenSearchTlsMode(openSearchTlsMode);
        }

        /** Returns the configured file cap converted to bytes for runtime enforcement. */
        public long fileTotalCapBytes() {
            return gbToBytes(fileTotalCapGb);
        }

        public Sinks(boolean filesEnabled, String filesPath,
                     boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     String openSearchTlsMode) {
            this(filesEnabled, filesPath, fileJsonlEnabled, fileBulkNdjsonEnabled,
                    true, DEFAULT_FILE_TOTAL_CAP_GB,
                    true, DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword, openSearchTlsMode);
        }

        public Sinks(boolean filesEnabled, String filesPath, boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                     boolean fileTotalCapEnabled, double fileTotalCapGb,
                     boolean fileDiskUsagePercentEnabled, int fileDiskUsagePercent,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     boolean openSearchInsecureSsl) {
            this(filesEnabled, filesPath, fileJsonlEnabled, fileBulkNdjsonEnabled,
                    fileTotalCapEnabled, fileTotalCapGb,
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
         * Convenience constructor for call sites that do not need to specify file formats.
         *
         * <p>When used, file export formats default to disabled until explicitly selected in the
         * UI or config.</p>
         */
        public Sinks(boolean filesEnabled, String filesPath,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     String openSearchTlsMode) {
            this(filesEnabled, filesPath, false, false,
                    true, DEFAULT_FILE_TOTAL_CAP_GB,
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
    public record LogPanelPreferences(
            String minLevel,
            boolean pauseAutoscroll,
            String filterText,
            boolean filterCase,
            boolean filterRegex,
            String searchText,
            boolean searchCase,
            boolean searchRegex) {
        public LogPanelPreferences {
            minLevel = normalizeLogMinLevel(minLevel);
            filterText = filterText == null ? "" : filterText;
            searchText = searchText == null ? "" : searchText;
        }
    }

    /** Persisted UI preferences that should survive save/export/import. */
    public record UiPreferences(int statsChartStyle, LogPanelPreferences logPanel) {
        public UiPreferences {
            statsChartStyle = Math.clamp(statsChartStyle, 1, 3);
            logPanel = logPanel == null ? defaultLogPanelPreferences() : logPanel;
        }
    }

    public record State(List<String> dataSources,
                        String scopeType,               // "all" | "burp" | "custom"
                        List<ScopeEntry> customEntries, // ordered; used when scopeType=custom
                        Sinks sinks,
                        List<String> settingsSub,       // "project", "user"; default both
                        List<String> trafficToolTypes,  // ToolType names; default empty (no traffic)
                        List<String> findingsSeverities, // AuditIssueSeverity names; default all five
                        Map<String, Set<String>> enabledExportFieldsByIndex, // index shortName -> enabled toggleable field keys; null = all enabled
                        UiPreferences uiPreferences) {

        public State {
            dataSources       = normalizeDataSources(dataSources);
            scopeType         = normalizeScopeType(scopeType);
            customEntries     = customEntries == null ? List.of() : List.copyOf(customEntries);
            settingsSub       = normalizeSettingsSub(settingsSub);
            trafficToolTypes  = normalizeTrafficToolTypes(trafficToolTypes);
            findingsSeverities = normalizeFindingsSeverities(findingsSeverities);
            enabledExportFieldsByIndex = enabledExportFieldsByIndex == null ? null : copyMapOfSets(enabledExportFieldsByIndex);
            uiPreferences = uiPreferences == null ? defaultUiPreferences() : uiPreferences;
        }

        public State(List<String> dataSources,
                     String scopeType,
                     List<ScopeEntry> customEntries,
                     Sinks sinks,
                     List<String> settingsSub,
                     List<String> trafficToolTypes,
                     List<String> findingsSeverities,
                     Map<String, Set<String>> enabledExportFieldsByIndex) {
            this(dataSources, scopeType, customEntries, sinks, settingsSub, trafficToolTypes,
                    findingsSeverities, enabledExportFieldsByIndex, defaultUiPreferences());
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

    /** Default persisted LogPanel preferences. */
    public static LogPanelPreferences defaultLogPanelPreferences() {
        return new LogPanelPreferences(DEFAULT_LOG_MIN_LEVEL, false, "", false, false, "", false, false);
    }

    /** Default persisted UI preferences. */
    public static UiPreferences defaultUiPreferences() {
        return new UiPreferences(DEFAULT_STATS_CHART_STYLE, defaultLogPanelPreferences());
    }

    /** Converts a human-friendly GB value to runtime bytes using half-up rounding. */
    public static long gbToBytes(double gb) {
        BigDecimal normalized = BigDecimal.valueOf(normalizeFileTotalCapGb(gb));
        BigDecimal bytes = normalized.multiply(GB_BYTES_DECIMAL).setScale(0, RoundingMode.HALF_UP);
        if (bytes.compareTo(LONG_MAX_DECIMAL) > 0) {
            return Long.MAX_VALUE;
        }
        return bytes.longValueExact();
    }

    /** Converts runtime bytes to the human-friendly GB value used in config state/export. */
    public static double bytesToGb(long bytes) {
        if (bytes <= 0) {
            return DEFAULT_FILE_TOTAL_CAP_GB;
        }
        return BigDecimal.valueOf(bytes)
                .divide(GB_BYTES_DECIMAL, 12, RoundingMode.HALF_UP)
                .doubleValue();
    }

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

    /** Returns one of trace/debug/info/warn/error, defaulting to trace. */
    public static String normalizeLogMinLevel(String raw) {
        if (raw == null || raw.isBlank()) {
            return DEFAULT_LOG_MIN_LEVEL;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "trace", "debug", "info", "warn", "error" -> raw.trim().toLowerCase(Locale.ROOT);
            default -> DEFAULT_LOG_MIN_LEVEL;
        };
    }

    /** Normalizes stored file-cap GB values and falls back to the default when unset or invalid. */
    public static double normalizeFileTotalCapGb(double raw) {
        return raw > 0d ? raw : DEFAULT_FILE_TOTAL_CAP_GB;
    }

    /** Normalizes config data-source ids to lowercase. */
    public static List<String> normalizeDataSources(List<String> values) {
        return normalizeLowercaseList(values);
    }

    /** Normalizes settings sub-option ids to lowercase. */
    public static List<String> normalizeSettingsSub(List<String> values) {
        return normalizeLowercaseList(values);
    }

    /** Normalizes traffic tool ids to lowercase. */
    public static List<String> normalizeTrafficToolTypes(List<String> values) {
        return normalizeLowercaseList(values);
    }

    /** Normalizes finding severity ids to lowercase. */
    public static List<String> normalizeFindingsSeverities(List<String> values) {
        return normalizeLowercaseList(values);
    }

    /** Normalizes persisted scope type values to lowercase supported ids. */
    public static String normalizeScopeType(String raw) {
        if (raw == null || raw.isBlank()) {
            return "all";
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "burp", "custom" -> raw.trim().toLowerCase(Locale.ROOT);
            default -> "all";
        };
    }

    private static List<String> normalizeLowercaseList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        for (String value : values) {
            if (value == null || value.isBlank()) {
                continue;
            }
            normalized.add(value.trim().toLowerCase(Locale.ROOT));
        }
        return List.copyOf(normalized);
    }
}
