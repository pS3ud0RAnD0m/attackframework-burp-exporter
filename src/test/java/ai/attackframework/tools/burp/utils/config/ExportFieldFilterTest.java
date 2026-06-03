package ai.attackframework.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

class ExportFieldFilterTest {

    @Test
    void filterDocument_copiesEnabledNestedFields_withoutWholeParent() {
        ConfigState.State original = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    null,
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    Map.of("settings", Set.of("burp.project_id", "project"))
            ));

            Map<String, Object> document = new LinkedHashMap<>();
            document.put("burp", Map.of("project_id", "project-1", "version", "2026.4"));
            document.put("meta", Map.of("schema_version", "1"));
            document.put("project", Map.of("project_options", Map.of("test_key", "project_value")));
            document.put("user", Map.of("user_options", Map.of("test_key", "user_value")));

            Map<String, Object> filtered = ExportFieldFilter.filterDocument(document, "settings");

            assertThat(filtered).containsKeys("burp", "meta", "project");
            assertThat(filtered.get("burp")).isEqualTo(Map.of("project_id", "project-1"));
            assertThat(filtered).doesNotContainKey("user");
        } finally {
            RuntimeConfig.updateState(original);
        }
    }

    @Test
    void filterDocument_emptyEnabledSetMeansNoOptionalFields() {
        ConfigState.State original = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    null,
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    Map.of("settings", Set.of())
            ));

            Map<String, Object> document = new LinkedHashMap<>();
            document.put("burp", Map.of("project_id", "project-1"));
            document.put("meta", Map.of("schema_version", "1"));
            document.put("project", Map.of("project_options", Map.of("test_key", "project_value")));

            Map<String, Object> filtered = ExportFieldFilter.filterDocument(document, "settings");

            assertThat(filtered).containsOnlyKeys("meta");
        } finally {
            RuntimeConfig.updateState(original);
        }
    }
}
