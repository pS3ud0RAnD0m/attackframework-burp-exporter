package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.StringKeyedMaps;

/**
 * Writes shared Repeater tab/group metadata fields into traffic documents.
 *
 * <p>Both historic Repeater snapshots and live HTTP traffic store metadata under
 * {@code burp.repeater.tab_name} and {@code burp.repeater.tab_group} per {@code traffic.json}.</p>
 */
final class RepeaterMetadataFields {

    record Metadata(String tabName, String groupName) {
        Metadata {
            tabName = normalizeBlank(tabName);
            groupName = normalizeBlank(groupName);
        }

        static Metadata empty() {
            return new Metadata(null, null);
        }

        boolean isPresent() {
            return tabName != null || groupName != null;
        }
    }

    private RepeaterMetadataFields() { }

    /**
     * Adds {@code burp.repeater.tab_name} and {@code burp.repeater.tab_group} when either value is set.
     *
     * @param document traffic document under construction
     * @param tabName repeater tab label, or blank to omit
     * @param groupName repeater group label, or blank to omit
     */
    static void put(Map<String, Object> document, String tabName, String groupName) {
        put(document, new Metadata(tabName, groupName));
    }

    static void put(Map<String, Object> document, Metadata metadata) {
        if (document == null) {
            return;
        }
        Metadata value = metadata == null ? Metadata.empty() : metadata;
        Map<String, Object> burp = StringKeyedMaps.nested(document, "burp", LinkedHashMap::new);
        Map<String, Object> repeater = StringKeyedMaps.nested(burp, "repeater", LinkedHashMap::new);
        repeater.put("tab_name", value.tabName());
        repeater.put("tab_group", value.groupName());
    }

    private static String normalizeBlank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
