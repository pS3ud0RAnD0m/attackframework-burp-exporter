package ai.attackframework.tools.burp.utils.config;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Defines the canonical export fields for each index.
 *
 * <p>This registry backs both the Fields panel and document filtering. Fields marked required in
 * the reference documentation always remain enabled; toggleable fields map to the optional
 * checkboxes shown in the UI.</p>
 */
public final class ExportFieldRegistry {

    private static final Map<String, List<String>> TOGGLEABLE_BY_INDEX = new LinkedHashMap<>();
    private static final Map<String, List<String>> REQUIRED_BY_INDEX = new LinkedHashMap<>();

    static {
        // Traffic index toggleable fields. Required fields remain in REQUIRED_BY_INDEX.
        TOGGLEABLE_BY_INDEX.put("traffic", List.of(
                "url", "host", "port", "scheme", "protocol_transport", "protocol_application", "protocol_sub",
                "http_version", "tool", "tool_type", "burp_in_scope", "message_id", "time_start", "time_end", "duration_ms",
                "comment", "highlight", "edited", "path", "method", "mime_type", "repeater_tab_name", "repeater_group_name",
                "websocket_id", "ws_message_id", "ws_direction", "ws_message_type", "ws_payload", "ws_payload_text",
                "ws_payload_length", "ws_edited", "ws_edited_payload", "ws_upgrade_request", "ws_time",
                "proxy_history_id", "listener_port", "time_request_sent", "response_start_latency_ms"
        ));
        REQUIRED_BY_INDEX.put("traffic", List.of(
                "status", "request", "response",
                "document_meta"  // whole object; subfields schema_version, extension_version, indexed_at
        ));

        // Exporter index fields.
        TOGGLEABLE_BY_INDEX.put("exporter", List.of(
                "level", "message_text", "message", "thread", "extension_version", "burp_version", "project_id"
        ));
        REQUIRED_BY_INDEX.put("exporter", List.of("event_type", "source", "document_meta"));

        // Settings index fields.
        TOGGLEABLE_BY_INDEX.put("settings", List.of("project_id", "settings_user", "settings_project"));
        REQUIRED_BY_INDEX.put("settings", List.of("document_meta"));

        // Sitemap index fields.
        TOGGLEABLE_BY_INDEX.put("sitemap", List.of(
                "url", "host", "port", "protocol_transport", "protocol_application", "protocol_sub",
                "method", "status_code", "status_reason", "content_type", "content_length", "title",
                "param_names", "path", "query_string", "request_id", "source"
        ));
        REQUIRED_BY_INDEX.put("sitemap", List.of("request", "response", "document_meta"));

        // Findings index fields.
        TOGGLEABLE_BY_INDEX.put("findings", List.of(
                "name", "severity", "confidence", "host", "port", "protocol_transport", "protocol_application", "protocol_sub",
                "url", "param", "issue_type_id", "typical_severity", "description", "background",
                "remediation_background", "remediation_detail", "references", "classifications"
        ));
        REQUIRED_BY_INDEX.put("findings", List.of("request_responses", "request_responses_missing", "document_meta"));
    }

    /** Index short names in internal display order. */
    public static final List<String> INDEX_ORDER = List.of("exporter", "traffic", "settings", "sitemap", "findings");

    /** Index order shown in the Fields panel. */
    public static final List<String> INDEX_ORDER_FOR_FIELDS_PANEL = List.of("settings", "sitemap", "findings", "traffic", "exporter");

    private ExportFieldRegistry() { }

    /** Returns the toggleable field keys for the index as an unmodifiable list. */
    public static List<String> getToggleableFields(String indexShortName) {
        List<String> list = TOGGLEABLE_BY_INDEX.get(indexShortName);
        return list == null ? List.of() : Collections.unmodifiableList(list);
    }

    /** Returns the required top-level field keys for the index as an unmodifiable list. */
    public static List<String> getRequiredFields(String indexShortName) {
        List<String> list = REQUIRED_BY_INDEX.get(indexShortName);
        return list == null ? List.of() : Collections.unmodifiableList(list);
    }

    /**
     * Returns the field keys allowed for documents written to the index.
     *
     * <p>The result always contains the required keys. When {@code enabledToggleable} is null or
     * empty, all toggleable keys are included. Otherwise only the selected toggleable keys are
     * added.</p>
     */
    public static Set<String> getAllowedKeys(String indexShortName, Set<String> enabledToggleable) {
        Set<String> out = new java.util.LinkedHashSet<>(getRequiredFields(indexShortName));
        List<String> toggleable = getToggleableFields(indexShortName);
        if (enabledToggleable == null || enabledToggleable.isEmpty()) {
            out.addAll(toggleable);
        } else {
            for (String f : toggleable) {
                if (enabledToggleable.contains(f)) out.add(f);
            }
        }
        return Collections.unmodifiableSet(out);
    }
}
