package ai.attackframework.tools.burp.utils.config;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Filters a document map to only include keys allowed for export for the given index.
 * Used before push so disabled fields (Fields panel) are not sent to OpenSearch.
 */
public final class ExportFieldFilter {

    private ExportFieldFilter() { }

    /**
     * Returns a new map containing only top-level keys that are allowed for this index.
     * When no field selection is configured, all keys are allowed (no change in behaviour).
     */
    public static Map<String, Object> filterDocument(Map<String, Object> document, String indexKey) {
        if (document == null) return Map.of();
        Set<String> allowed = RuntimeConfig.getAllowedExportKeys(indexKey);
        Map<String, Object> out = new LinkedHashMap<>();
        for (String key : allowed) {
            if (document.containsKey(key)) {
                out.put(key, document.get(key));
            }
        }
        return out;
    }
}
