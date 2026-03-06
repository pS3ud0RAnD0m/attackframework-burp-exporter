package ai.attackframework.tools.burp.utils.config;

import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ExportFieldRegistry}: Fields panel order, toggleable/required lists, and allowed-keys logic.
 */
class ExportFieldRegistryTest {

    @Test
    void index_order_for_fields_panel_excludes_tool_and_matches_config_sources_order() {
        assertThat(ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL)
                .containsExactly("settings", "sitemap", "findings", "traffic");
        assertThat(ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL).doesNotContain("tool");
    }

    @Test
    void get_toggleable_fields_returns_non_empty_for_each_fields_panel_index() {
        for (String index : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            assertThat(ExportFieldRegistry.getToggleableFields(index))
                    .as("toggleable for " + index)
                    .isNotEmpty();
        }
    }

    @Test
    void get_allowed_keys_with_null_enabled_returns_required_plus_all_toggleable() {
        String index = "traffic";
        Set<String> allowed = ExportFieldRegistry.getAllowedKeys(index, null);
        assertThat(allowed).containsAll(ExportFieldRegistry.getRequiredFields(index));
        assertThat(allowed).containsAll(ExportFieldRegistry.getToggleableFields(index));
    }

    @Test
    void get_allowed_keys_with_partial_enabled_returns_required_plus_only_those_toggleable() {
        String index = "settings";
        Set<String> enabledToggleable = Set.of("project_id");
        Set<String> allowed = ExportFieldRegistry.getAllowedKeys(index, enabledToggleable);
        assertThat(allowed).containsAll(ExportFieldRegistry.getRequiredFields(index));
        assertThat(allowed).contains("project_id");
        assertThat(allowed).doesNotContain("settings_user").doesNotContain("settings_project");
    }
}
