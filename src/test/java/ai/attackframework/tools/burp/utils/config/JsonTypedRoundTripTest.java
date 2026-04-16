package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class JsonTypedRoundTripTest {

    @Test
    void build_and_parse_typed_custom_scope_preserves_order_and_kinds() throws IOException {
        List<String> sources = List.of("settings", "traffic");

        var state = new ConfigState.State(
                sources, "custom",
                List.of(
                        new ConfigState.ScopeEntry("x", ConfigState.Kind.REGEX),
                        new ConfigState.ScopeEntry("y", ConfigState.Kind.STRING)
                ),
                new ConfigState.Sinks(true, "/path/to/directory", true, true,
                        true, 7d,
                        true, 91,
                        true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS, ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null
        );

        String json = ConfigJsonMapper.build(state);
        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(json).contains("\"totalGb\" : 7.0");
        assertThat(json).doesNotContain("totalBytes");
        assertThat(parsed.dataSources()).containsExactlyElementsOf(sources);
        assertThat(parsed.scopeType()).isEqualTo("custom");
        assertThat(parsed.scopeRegexes()).containsExactly("x", "y");
        assertThat(parsed.filesPath()).isEqualTo("/path/to/directory");
        assertThat(parsed.fileJsonlEnabled()).isTrue();
        assertThat(parsed.fileBulkNdjsonEnabled()).isTrue();
        assertThat(parsed.fileTotalCapEnabled()).isTrue();
        assertThat(parsed.fileTotalCapGb()).isEqualTo(7d);
        assertThat(parsed.fileDiskUsagePercentEnabled()).isTrue();
        assertThat(parsed.fileDiskUsagePercent()).isEqualTo(91);
        assertThat(parsed.openSearchUrl()).isEqualTo("https://opensearch.url:9200");
    }

    @Test
    void build_all_scope_sets_flag_only() throws IOException {
        var state = new ConfigState.State(
                List.of("settings"), "all", null,
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);
        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(parsed.scopeType()).isEqualTo("all");
        assertThat(parsed.scopeRegexes()).isEmpty();
    }

    @Test
    void build_burp_scope_sets_flag_only() throws IOException {
        var state = new ConfigState.State(
                List.of("traffic"), "burp", null,
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);
        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(parsed.scopeType()).isEqualTo("burp");
        assertThat(parsed.scopeRegexes()).isEmpty();
    }

    @Test
    void build_and_parse_preserves_data_source_sub_options() throws IOException {
        var state = new ConfigState.State(
                List.of("settings", "traffic", "findings"), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                List.of(ConfigKeys.SRC_SETTINGS_PROJECT),
                List.of("proxy", "repeater"),
                List.of("high", "critical"),
                List.of(ConfigKeys.SRC_EXPORTER_INFO, ConfigKeys.SRC_EXPORTER_STATS),
                45,
                null
        );

        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parse(json);

        assertThat(json).contains("\"traffic\"");
        assertThat(json).contains("\"proxy\"");
        assertThat(json).contains("\"repeater\"");
        assertThat(json).contains("\"findings\"");
        assertThat(json).contains("\"high\"");
        assertThat(json).contains("\"critical\"");
        assertThat(json).contains("\"exporter\"");
        assertThat(json).contains("\"exporterStatsIntervalSeconds\" : 45");
        assertThat(parsed.settingsSub()).containsExactly(ConfigKeys.SRC_SETTINGS_PROJECT);
        assertThat(parsed.trafficToolTypes()).containsExactly("proxy", "repeater");
        assertThat(parsed.findingsSeverities()).containsExactlyInAnyOrder("high", "critical");
        assertThat(parsed.exporterSubOptions()).containsExactly(ConfigKeys.SRC_EXPORTER_INFO, ConfigKeys.SRC_EXPORTER_STATS);
        assertThat(parsed.exporterStatsIntervalSeconds()).isEqualTo(45);
    }

    @Test
    void build_and_parse_preserves_proxy_history_in_traffic_tool_types() throws IOException {
        var state = new ConfigState.State(
                List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy", "proxy_history", "repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null
        );
        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parse(json);
        assertThat(parsed.trafficToolTypes()).containsExactlyInAnyOrder("proxy", "proxy_history", "repeater");
    }

    @Test
    void parse_json_without_dataSourceOptions_uses_current_defaults() throws IOException {
        String legacy = """
            {"version":"1.0","dataSources":["traffic"],"scope":["burp"],"sinks":{}}
            """;
        ConfigState.State parsed = ConfigJsonMapper.parse(legacy);
        assertThat(parsed.dataSources()).contains("traffic", ConfigKeys.SRC_EXPORTER);
        assertThat(parsed.trafficToolTypes()).containsExactly(
                "burp_ai", "extensions", "intruder", "proxy",
                "proxy_history", "repeater", "scanner", "sequencer");
        assertThat(parsed.settingsSub()).containsExactlyInAnyOrder(ConfigKeys.SRC_SETTINGS_PROJECT, ConfigKeys.SRC_SETTINGS_USER);
        assertThat(parsed.findingsSeverities()).containsExactlyInAnyOrder("critical", "high", "medium", "low", "informational");
        assertThat(parsed.exporterSubOptions()).containsExactlyElementsOf(ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS);
        assertThat(parsed.exporterStatsIntervalSeconds()).isEqualTo(ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS);
    }

    @Test
    void parse_json_with_explicit_empty_exporter_options_preserves_disabled_exporter_sub_options() throws IOException {
        String json = """
            {
              "version": "1.0",
              "dataSources": ["exporter"],
              "scope": ["all"],
              "sinks": {},
              "dataSourceOptions": {
                "settings": ["project", "user"],
                "traffic": [],
                "findings": ["critical", "high", "medium", "low", "informational"],
                "exporter": [],
                "exporterStatsIntervalSeconds": 15
              }
            }
            """;

        ConfigState.State parsed = ConfigJsonMapper.parse(json);

        assertThat(parsed.dataSources()).containsExactly(ConfigKeys.SRC_EXPORTER);
        assertThat(parsed.exporterSubOptions()).isEmpty();
        assertThat(parsed.exporterStatsIntervalSeconds()).isEqualTo(15);
    }

    @Test
    void build_and_parse_preserves_exportFields_when_present() throws IOException {
        Map<String, Set<String>> enabledByIndex = Map.of(
                "traffic", Set.of("url", "host", "method"),
                "settings", Set.of("project_id")
        );
        var state = new ConfigState.State(
                List.of("settings", "traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS, ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                enabledByIndex
        );
        String json = ConfigJsonMapper.build(state);
        assertThat(json).contains("exportFields");
        ConfigState.State parsed = ConfigJsonMapper.parse(json);
        assertThat(parsed.enabledExportFieldsByIndex()).isNotNull();
        assertThat(parsed.enabledExportFieldsByIndex().get("traffic")).containsExactlyInAnyOrder("url", "host", "method");
        assertThat(parsed.enabledExportFieldsByIndex().get("settings")).containsExactly("project_id");
    }

    @Test
    void parse_json_without_exportFields_returns_null_enabledExportFieldsByIndex() throws IOException {
        String json = """
            {"version":"1.0","dataSources":["settings"],"scope":["all"],"sinks":{},"dataSourceOptions":{"settings":["project","user"],"traffic":[],"findings":["critical","high","medium","low","informational"]}}
            """;
        ConfigState.State parsed = ConfigJsonMapper.parse(json);
        assertThat(parsed.enabledExportFieldsByIndex()).isNull();
    }

    @Test
    void build_and_parse_preserves_ui_preferences_for_stats_and_log_panel() throws IOException {
        var state = new ConfigState.State(
                List.of("settings"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null,
                new ConfigState.UiPreferences(
                        2,
                        new ConfigState.LogPanelPreferences("warn", true, "tls", true, false, "retry", false, true)));

        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parse(json);

        assertThat(json).contains("\"minLevel\" : \"warn\"");
        assertThat(parsed.uiPreferences().statsChartStyle()).isEqualTo(2);
        assertThat(parsed.uiPreferences().logPanel().minLevel()).isEqualTo("warn");
        assertThat(parsed.uiPreferences().logPanel().pauseAutoscroll()).isTrue();
        assertThat(parsed.uiPreferences().logPanel().filterText()).isEqualTo("tls");
        assertThat(parsed.uiPreferences().logPanel().filterCase()).isTrue();
        assertThat(parsed.uiPreferences().logPanel().filterRegex()).isFalse();
        assertThat(parsed.uiPreferences().logPanel().searchText()).isEqualTo("retry");
        assertThat(parsed.uiPreferences().logPanel().searchCase()).isFalse();
        assertThat(parsed.uiPreferences().logPanel().searchRegex()).isTrue();
    }
}
