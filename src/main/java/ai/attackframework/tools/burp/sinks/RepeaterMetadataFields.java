package ai.attackframework.tools.burp.sinks;

import java.util.Map;

/**
 * Writes shared Repeater tab/group metadata fields into traffic documents.
 *
 * <p>Both historic Repeater snapshots and live HTTP traffic use the same field names in the
 * traffic index. Centralizing the writes here keeps document shape consistent across history
 * capture and live Repeater correlation without duplicating field-name literals.</p>
 */
final class RepeaterMetadataFields {

    static final String TAB_NAME_FIELD = "repeater_tab_name";
    static final String GROUP_NAME_FIELD = "repeater_group_name";

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

    private RepeaterMetadataFields() {}

    static void put(Map<String, Object> document, String tabName, String groupName) {
        put(document, new Metadata(tabName, groupName));
    }

    static void put(Map<String, Object> document, Metadata metadata) {
        if (document == null) {
            return;
        }
        Metadata value = metadata == null ? Metadata.empty() : metadata;
        document.put(TAB_NAME_FIELD, value.tabName());
        document.put(GROUP_NAME_FIELD, value.groupName());
    }

    private static String normalizeBlank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
