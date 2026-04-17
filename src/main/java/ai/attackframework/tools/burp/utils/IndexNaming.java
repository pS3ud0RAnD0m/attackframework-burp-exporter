package ai.attackframework.tools.burp.utils;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ai.attackframework.tools.burp.utils.config.ConfigState;

/**
 * Maps between logical index keys and the concrete names used for OpenSearch and file export.
 *
 * <p>Index names are derived from one global base template. The default base is
 * {@value #DEFAULT_BASE_TEMPLATE}, which produces these default names:
 * {@code attackframework-tool-burp-exporter}, {@code ...-findings}, {@code ...-settings},
 * {@code ...-sitemap}, and {@code ...-traffic}.</p>
 */
public final class IndexNaming {
    public static final String DEFAULT_BASE_TEMPLATE = "attackframework-tool-burp";
    /** Legacy default Exporter index name retained only for import/back-compat inference. */
    public static final String LEGACY_TOOL_INDEX_NAME = DEFAULT_BASE_TEMPLATE;
    public static final String INDEX_PREFIX = DEFAULT_BASE_TEMPLATE;

    private static final String DEFAULT_NOW_FORMAT = "yyyyMMdd-HHmmss";
    private static final String DEFAULT_DATE_ONLY_FORMAT = "yyyyMMdd";
    private static final Pattern NOW_TEMPLATE = Pattern.compile("\\$\\{now:([^}]+)}");
    private static final Set<Character> INVALID_INDEX_CHARS = Set.of(
            '\\', '/', '*', '?', '"', '<', '>', '|', ' ', ',', '#', ':');

    private static final List<String> INDEX_KEYS = List.of("tool", "findings", "settings", "sitemap", "traffic");
    private static final Map<String, String> DEFAULT_SUFFIXES = Map.of(
            "tool", "exporter",
            "findings", "findings",
            "settings", "settings",
            "sitemap", "sitemap",
            "traffic", "traffic");

    private IndexNaming() { }

    /** Returns the supported logical index keys in display/order-stable form. */
    public static List<String> indexKeys() {
        return INDEX_KEYS;
    }

    /** Returns the default concrete index name for the given short name. */
    public static String indexNameForShortName(String shortName) {
        return defaultTemplateForShortName(shortName, DEFAULT_BASE_TEMPLATE);
    }

    /** Returns the default template for the given short name using the provided base template. */
    public static String defaultTemplateForShortName(String shortName, String baseTemplate) {
        String normalizedKey = shortName == null ? "" : shortName.trim().toLowerCase(Locale.ROOT);
        String normalizedBase = normalizeBaseTemplate(baseTemplate);
        String suffix = normalizedKey.isBlank()
                ? suffixForIndex("tool")
                : DEFAULT_SUFFIXES.getOrDefault(normalizedKey, normalizedKey);
        return normalizedBase + "-" + suffix;
    }

    /** Returns the configured template for the given logical index key. */
    public static String configuredTemplateForShortName(ConfigState.State state, String shortName) {
        String normalizedKey = shortName == null ? "" : shortName.trim().toLowerCase(Locale.ROOT);
        String baseTemplate = state == null ? DEFAULT_BASE_TEMPLATE : state.indexNameBaseTemplate();
        return defaultTemplateForShortName(normalizedKey, baseTemplate);
    }

    /** Resolves the configured template for one logical index key at the provided instant. */
    public static String resolveConfiguredIndexName(ConfigState.State state, String shortName, Instant instant) {
        return resolveTemplate(configuredTemplateForShortName(state, shortName), instant);
    }

    /**
     * Resolves every configured logical index name at the provided instant and validates them.
     *
     * <p>Errors include invalid date/time placeholders, unsupported variable syntax, and invalid
     * OpenSearch index names.</p>
     */
    public static ResolutionResult resolveAllConfiguredNames(ConfigState.State state, Instant instant) {
        Instant effectiveInstant = instant == null ? Instant.now() : instant;
        LinkedHashMap<String, String> namesByKey = new LinkedHashMap<>();
        List<String> errors = new ArrayList<>();

        for (String indexKey : INDEX_KEYS) {
            String template = configuredTemplateForShortName(state, indexKey);
            try {
                String resolved = resolveTemplate(template, effectiveInstant);
                String validationError = validateResolvedName(resolved);
                if (validationError != null) {
                    errors.add(indexKey + ": " + validationError);
                }
                namesByKey.put(indexKey, resolved);
            } catch (IllegalArgumentException e) {
                errors.add(indexKey + ": " + e.getMessage());
                namesByKey.put(indexKey, template);
            }
        }
        return new ResolutionResult(Map.copyOf(namesByKey), List.copyOf(errors), effectiveInstant);
    }

    /**
     * Returns the logical key only for default or legacy index names that can be safely inferred.
     *
     * <p>Custom configured index names are intentionally rejected so callers do not silently
     * misroute field filtering, stats, or retry accounting by guessing from a physical name.</p>
     *
     * @throws IllegalArgumentException when the provided name is not one of the known default or
     *                                  legacy index names
     */
    public static String requireKnownIndexKey(String indexName) {
        if (indexName == null || indexName.isBlank()) {
            throw new IllegalArgumentException("index name is blank; explicit logical index key is required.");
        }
        String normalized = indexName.trim().toLowerCase(Locale.ROOT);
        if (normalized.equals(LEGACY_TOOL_INDEX_NAME) || normalized.equals(indexNameForShortName("tool"))) {
            return "tool";
        }
        for (String key : INDEX_KEYS) {
            if (normalized.equals(indexNameForShortName(key))) {
                return key;
            }
        }
        throw new IllegalArgumentException(
                "custom index name '" + indexName + "' cannot be reversed into a logical key; pass the logical index key explicitly.");
    }

    /** Returns the user-facing display name for one logical index key. */
    public static String displayNameForIndexKey(String indexKey) {
        String normalized = indexKey == null ? "" : indexKey.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "tool" -> "Exporter";
            case "findings" -> "Findings";
            case "settings" -> "Settings";
            case "sitemap" -> "Sitemap";
            case "traffic" -> "Traffic";
            default -> normalized;
        };
    }

    /**
     * Returns the logical index keys required by the selected sources.
     *
     * <p>Unsupported source names are ignored. The Exporter index is included only when the
     * {@code exporter} source is selected.</p>
     */
    public static List<String> computeSelectedIndexKeys(List<String> selectedSources) {
        LinkedHashSet<String> keys = new LinkedHashSet<>();
        if (selectedSources != null) {
            for (String source : selectedSources) {
                if (source == null) {
                    continue;
                }
                switch (source.trim().toLowerCase(Locale.ROOT)) {
                    case "exporter" -> keys.add("tool");
                    case "settings" -> keys.add("settings");
                    case "sitemap" -> keys.add("sitemap");
                    case "issues", "findings" -> keys.add("findings");
                    case "traffic" -> keys.add("traffic");
                    default -> {
                        // Ignore unsupported source names; no index will be created for them.
                    }
                }
            }
        }
        return new ArrayList<>(keys);
    }

    /** Returns the default concrete index names required by the selected sources. */
    public static List<String> computeIndexBaseNames(List<String> selectedSources) {
        List<String> names = new ArrayList<>();
        for (String indexKey : computeSelectedIndexKeys(selectedSources)) {
            names.add(indexNameForShortName(indexKey));
        }
        return names;
    }

    /** Returns {@code .json} mapping-file names for the provided index base names. */
    public static List<String> toJsonFileNames(List<String> baseNames) {
        List<String> out = new ArrayList<>(baseNames.size());
        for (String baseName : baseNames) {
            out.add(baseName + ".json");
        }
        return out;
    }

    /** Returns export data file names for the selected on-disk formats. */
    public static List<String> toExportFileNames(List<String> baseNames, boolean jsonlEnabled, boolean bulkNdjsonEnabled) {
        List<String> out = new ArrayList<>();
        for (String baseName : baseNames) {
            if (jsonlEnabled) {
                out.add(baseName + ".jsonl");
            }
            if (bulkNdjsonEnabled) {
                out.add(baseName + ".ndjson");
            }
        }
        return out;
    }

    /** Normalizes the stored global base template and falls back to the default when blank. */
    public static String normalizeBaseTemplate(String template) {
        return template == null || template.isBlank() ? DEFAULT_BASE_TEMPLATE : template.trim();
    }

    /** Replaces supported date/time variables in the provided template. */
    public static String resolveTemplate(String template, Instant instant) {
        String value = template == null ? "" : template.trim();
        Instant effectiveInstant = instant == null ? Instant.now() : instant;
        value = value.replace("{NOW}", formatNow(effectiveInstant, DEFAULT_NOW_FORMAT));
        value = value.replace("{DATE-TIME}", formatNow(effectiveInstant, DEFAULT_NOW_FORMAT));
        value = value.replace("{DATE}", formatNow(effectiveInstant, DEFAULT_DATE_ONLY_FORMAT));

        Matcher matcher = NOW_TEMPLATE.matcher(value);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String format = matcher.group(1);
            String replacement = formatNow(effectiveInstant, format);
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /** Returns a human-readable validation error, or {@code null} when the resolved name is valid. */
    public static String validateResolvedName(String resolvedName) {
        if (resolvedName == null || resolvedName.isBlank()) {
            return "resolved name is blank.";
        }
        String normalized = resolvedName.trim();
        if (!normalized.equals(normalized.toLowerCase(Locale.ROOT))) {
            return "must be lowercase.";
        }
        if (normalized.equals(".") || normalized.equals("..")) {
            return "cannot be '.' or '..'.";
        }
        char first = normalized.charAt(0);
        if (first == '-' || first == '_' || first == '+') {
            return "cannot start with '-', '_', or '+'.";
        }
        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);
            if (INVALID_INDEX_CHARS.contains(c)) {
                return "contains unsupported character '" + c + "'.";
            }
        }
        if (normalized.contains("{") || normalized.contains("}") || normalized.contains("${")) {
            return "contains unsupported or unresolved variable syntax.";
        }
        if (normalized.getBytes(StandardCharsets.UTF_8).length > 255) {
            return "exceeds the 255-byte OpenSearch index-name limit.";
        }
        return null;
    }

    /**
     * Validates the global base template against the concrete index names it would produce.
     *
     * <p>Blank input is treated as valid because the UI falls back to the default base template.
     * Non-blank values must resolve into valid OpenSearch index names after the fixed suffix for
     * each logical index is appended.</p>
     */
    public static BaseTemplateValidation validateBaseTemplateDetailed(String baseTemplate, Instant instant) {
        if (baseTemplate == null || baseTemplate.isBlank()) {
            return new BaseTemplateValidation(null, null, null, instant == null ? Instant.now() : instant);
        }
        Instant effectiveInstant = instant == null ? Instant.now() : instant;
        String candidateBase = baseTemplate.trim();
        for (String indexKey : INDEX_KEYS) {
            String resolvedName;
            try {
                resolvedName = resolveTemplate(defaultTemplateForShortName(indexKey, candidateBase), effectiveInstant);
            } catch (IllegalArgumentException e) {
                return new BaseTemplateValidation(indexKey, defaultTemplateForShortName(indexKey, candidateBase), e.getMessage(), effectiveInstant);
            }
            String validationError = validateResolvedName(resolvedName);
            if (validationError != null) {
                return new BaseTemplateValidation(indexKey, resolvedName, validationError, effectiveInstant);
            }
        }
        return new BaseTemplateValidation(null, null, null, effectiveInstant);
    }

    /** Returns a human-readable validation error for the global base template, or {@code null}. */
    public static String validateBaseTemplate(String baseTemplate, Instant instant) {
        return validateBaseTemplateDetailed(baseTemplate, instant).error();
    }

    private static String suffixForIndex(String normalizedKey) {
        return Objects.requireNonNull(DEFAULT_SUFFIXES.get(normalizedKey), "Unknown index key: " + normalizedKey);
    }

    private static String formatNow(Instant instant, String format) {
        try {
            return DateTimeFormatter.ofPattern(format, Locale.ROOT)
                    .withZone(ZoneId.systemDefault())
                    .format(instant);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid ${now:...} format '" + format + "'.", e);
        }
    }

    /** Resolved index names for one configuration snapshot at one instant. */
    public record BaseTemplateValidation(
            String failingIndexKey,
            String failingResolvedName,
            String error,
            Instant resolvedAt
    ) {
        public boolean valid() {
            return error == null || error.isBlank();
        }

        public String failingDisplayName() {
            return valid() ? "" : displayNameForIndexKey(failingIndexKey);
        }
    }

    /** Resolved index names for one configuration snapshot at one instant. */
    public static final class ResolutionResult {
        private final Map<String, String> namesByKey;
        private final List<String> errors;
        private final Instant resolvedAt;

        public ResolutionResult(Map<String, String> namesByKey, List<String> errors, Instant resolvedAt) {
            this.namesByKey = namesByKey == null ? Map.of() : Map.copyOf(namesByKey);
            this.errors = errors == null ? List.of() : List.copyOf(errors);
            this.resolvedAt = resolvedAt == null ? Instant.now() : resolvedAt;
        }

        public Map<String, String> namesByKey() {
            return namesByKey;
        }

        public List<String> errors() {
            return errors;
        }

        public Instant resolvedAt() {
            return resolvedAt;
        }

        public boolean valid() {
            return errors.isEmpty();
        }
    }
}
