package ai.attackframework.tools.burp.utils.config;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Canonical list of export fields per index for the Fields panel and document filtering.
 * "Is required" column: toggleable = No or No*, required = Yes.
 * Keep this class as the single source of truth when adding or changing index fields.
 */
public final class ExportFieldRegistry {

    private static final Map<String, List<String>> TOGGLEABLE_BY_INDEX = new LinkedHashMap<>();
    private static final Map<String, List<String>> REQUIRED_BY_INDEX = new LinkedHashMap<>();

    static {
        // Traffic index: toggleable fields (No* and No). Required (Yes): status, request, response, document_meta.*
        TOGGLEABLE_BY_INDEX.put("traffic", List.of(
                "url", "host", "port", "scheme", "protocol_transport", "protocol_application", "protocol_sub",
                "http_version", "tool", "tool_type", "in_scope", "message_id", "time_start", "time_end", "duration_ms",
                "comment", "highlight", "edited", "path", "method", "mime_type",
                "websocket_id", "ws_message_id", "ws_direction", "ws_message_type", "ws_payload", "ws_payload_text",
                "ws_payload_length", "ws_edited", "ws_edited_payload", "ws_upgrade_request", "ws_time",
                "proxy_history_id", "listener_port", "time_request_sent", "response_start_latency_ms"
        ));
        REQUIRED_BY_INDEX.put("traffic", List.of(
                "status", "request", "response",
                "document_meta"  // whole object; subfields schema_version, extension_version, indexed_at
        ));

        // Tool index
        TOGGLEABLE_BY_INDEX.put("tool", List.of(
                "level", "message_text", "message", "thread", "extension_version", "burp_version", "project_id"
        ));
        REQUIRED_BY_INDEX.put("tool", List.of("event_type", "source", "document_meta"));

        // Settings index
        TOGGLEABLE_BY_INDEX.put("settings", List.of("project_id", "settings_user", "settings_project"));
        REQUIRED_BY_INDEX.put("settings", List.of("document_meta"));

        // Sitemap index
        TOGGLEABLE_BY_INDEX.put("sitemap", List.of(
                "url", "host", "port", "protocol_transport", "protocol_application", "protocol_sub",
                "method", "status_code", "status_reason", "content_type", "content_length", "title",
                "param_names", "path", "query_string", "request_id", "source"
        ));
        REQUIRED_BY_INDEX.put("sitemap", List.of("request", "response", "document_meta"));

        // Findings index
        TOGGLEABLE_BY_INDEX.put("findings", List.of(
                "name", "severity", "confidence", "host", "port", "protocol_transport", "protocol_application", "protocol_sub",
                "url", "param", "issue_type_id", "typical_severity", "description", "background",
                "remediation_background", "remediation_detail", "references", "classifications"
        ));
        REQUIRED_BY_INDEX.put("findings", List.of("request_responses", "request_responses_missing", "document_meta"));
    }

    /** Index short names in display order (tool, traffic, settings, sitemap, findings). */
    public static final List<String> INDEX_ORDER = List.of("tool", "traffic", "settings", "sitemap", "findings");

    /** Indexes shown in the Fields panel (excludes tool, which is administrative and not user-toggleable). Order matches ConfigSourcesPanel: Settings, Sitemap, Findings, Traffic. */
    public static final List<String> INDEX_ORDER_FOR_FIELDS_PANEL = List.of("settings", "sitemap", "findings", "traffic");

    private ExportFieldRegistry() { }

    /** Returns an unmodifiable list of toggleable field keys for the index (No / No* in REFERENCE). */
    public static List<String> getToggleableFields(String indexShortName) {
        List<String> list = TOGGLEABLE_BY_INDEX.get(indexShortName);
        return list == null ? List.of() : Collections.unmodifiableList(list);
    }

    /** Returns an unmodifiable list of required top-level keys for the index (Yes in REFERENCE). */
    public static List<String> getRequiredFields(String indexShortName) {
        List<String> list = REQUIRED_BY_INDEX.get(indexShortName);
        return list == null ? List.of() : Collections.unmodifiableList(list);
    }

    /**
     * Returns the set of field keys that may be included in documents for this index:
     * required + (enabledToggleable if provided, else all toggleable).
     * Used for document filtering (which fields to include in pushed documents).
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
