package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

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
                new ConfigState.Sinks(true, "/path/to/directory", true, "http://opensearch.url:9200"),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES
        );

        String json = ConfigJsonMapper.build(state);
        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(parsed.dataSources()).containsExactlyElementsOf(sources);
        assertThat(parsed.scopeType()).isEqualTo("custom");
        assertThat(parsed.scopeRegexes()).containsExactly("x", "y");
        assertThat(parsed.filesPath()).isEqualTo("/path/to/directory");
        assertThat(parsed.openSearchUrl()).isEqualTo("http://opensearch.url:9200");
    }

    @Test
    void build_all_scope_sets_flag_only() throws IOException {
        var state = new ConfigState.State(
                List.of("settings"), "all", null,
                new ConfigState.Sinks(false, null, false, null),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES
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
                new ConfigState.Sinks(false, null, false, null),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES
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
                new ConfigState.Sinks(false, null, false, null),
                List.of(ConfigKeys.SRC_SETTINGS_PROJECT),
                List.of("PROXY", "REPEATER"),
                List.of("HIGH", "CRITICAL")
        );

        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parse(json);

        assertThat(parsed.settingsSub()).containsExactly(ConfigKeys.SRC_SETTINGS_PROJECT);
        assertThat(parsed.trafficToolTypes()).containsExactly("PROXY", "REPEATER");
        assertThat(parsed.findingsSeverities()).containsExactlyInAnyOrder("HIGH", "CRITICAL");
    }

    @Test
    void build_and_parse_preserves_PROXY_HISTORY_in_traffic_tool_types() throws IOException {
        var state = new ConfigState.State(
                List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, false, null),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("PROXY", "PROXY_HISTORY", "REPEATER"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES
        );
        String json = ConfigJsonMapper.build(state);
        ConfigState.State parsed = ConfigJsonMapper.parse(json);
        assertThat(parsed.trafficToolTypes()).containsExactlyInAnyOrder("PROXY", "PROXY_HISTORY", "REPEATER");
    }

    @Test
    void parse_legacy_json_without_dataSourceOptions_uses_legacy_traffic_default() throws IOException {
        String legacy = """
            {"version":"1.0","dataSources":["traffic"],"scope":["burp"],"sinks":{}}
            """;
        ConfigState.State parsed = ConfigJsonMapper.parse(legacy);
        assertThat(parsed.trafficToolTypes()).containsExactlyInAnyOrder("PROXY", "REPEATER");
        assertThat(parsed.settingsSub()).containsExactlyInAnyOrder(ConfigKeys.SRC_SETTINGS_PROJECT, ConfigKeys.SRC_SETTINGS_USER);
        assertThat(parsed.findingsSeverities()).containsExactlyInAnyOrder("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL");
    }
}
