package ai.attackframework.tools.burp.utils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Maps between logical source or index names and concrete export index/file names.
 *
 * <p>The Tool index uses the bare prefix {@value #INDEX_PREFIX}. All other indices append their
 * short name as a suffix.</p>
 */
public final class IndexNaming {
    public static final String INDEX_PREFIX = "attackframework-tool-burp";

    private IndexNaming() {}

    /** Returns the concrete index name for the given short name. */
    public static String indexNameForShortName(String shortName) {
        if (shortName == null || shortName.isBlank() || "tool".equalsIgnoreCase(shortName)) {
            return INDEX_PREFIX;
        }
        return INDEX_PREFIX + "-" + shortName;
    }

    /** Returns the short name represented by the concrete index name. */
    public static String shortNameForIndexName(String indexName) {
        if (indexName == null || indexName.isBlank()) {
            return "tool";
        }
        if (indexName.equals(INDEX_PREFIX)) {
            return "tool";
        }
        if (indexName.startsWith(INDEX_PREFIX + "-")) {
            return indexName.substring(INDEX_PREFIX.length() + 1);
        }
        return "tool";
    }

    /**
     * Returns the concrete index names required by the selected sources.
     *
     * <p>Unsupported source names are ignored. The Tool index is included only when the
     * {@code exporter} source is selected.</p>
     */
    public static List<String> computeIndexBaseNames(List<String> selectedSources) {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        if (selectedSources != null) {
            for (String s : selectedSources) {
                if (s == null) continue;
                switch (s.toLowerCase()) {
                    case "exporter" -> names.add(indexNameForShortName("tool"));
                    case "settings" -> names.add(indexNameForShortName("settings"));
                    case "sitemap"  -> names.add(indexNameForShortName("sitemap"));
                    case "issues", "findings" -> names.add(indexNameForShortName("findings"));
                    case "traffic"  -> names.add(indexNameForShortName("traffic"));
                    default -> {
                        // Ignore unsupported source names; no index will be created for them.
                    }
                }
            }
        }
        return new ArrayList<>(names);
    }

    /** Returns {@code .json} mapping-file names for the provided index base names. */
    public static List<String> toJsonFileNames(List<String> baseNames) {
        List<String> out = new ArrayList<>(baseNames.size());
        for (String b : baseNames) out.add(b + ".json");
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
}
