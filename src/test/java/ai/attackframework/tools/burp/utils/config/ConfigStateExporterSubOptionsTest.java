package ai.attackframework.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

class ConfigStateExporterSubOptionsTest {

    @Test
    void defaultExporterSubOptions_includesTraceAndDebug() {
        assertThat(ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS)
                .containsExactly(
                        ConfigKeys.SRC_EXPORTER_TRACE,
                        ConfigKeys.SRC_EXPORTER_DEBUG,
                        ConfigKeys.SRC_EXPORTER_INFO,
                        ConfigKeys.SRC_EXPORTER_WARN,
                        ConfigKeys.SRC_EXPORTER_ERROR,
                        ConfigKeys.SRC_EXPORTER_STATS,
                        ConfigKeys.SRC_EXPORTER_CONFIG);
    }

    @Test
    void normalizeExporterSubOptions_preservesTraceAndDebug() {
        List<String> normalized = ConfigState.normalizeExporterSubOptions(List.of(
                ConfigKeys.SRC_EXPORTER_TRACE,
                ConfigKeys.SRC_EXPORTER_DEBUG,
                ConfigKeys.SRC_EXPORTER_INFO,
                ConfigKeys.SRC_EXPORTER_STATS));

        assertThat(normalized).containsExactly(
                ConfigKeys.SRC_EXPORTER_TRACE,
                ConfigKeys.SRC_EXPORTER_DEBUG,
                ConfigKeys.SRC_EXPORTER_INFO,
                ConfigKeys.SRC_EXPORTER_STATS);
    }

    @Test
    void parse_json_preservesTraceAndDebugFromExporterOptions() throws Exception {
        String json = """
            {
              "version": "1.0",
              "dataSources": ["exporter"],
              "scope": ["all"],
              "sinks": {},
              "dataSourceOptions": {
                "exporter": ["trace", "debug", "info", "stats"]
              }
            }
            """;
        ConfigState.State parsed = ConfigJsonMapper.parse(json);

        assertThat(parsed.exporterSubOptions())
                .containsExactly(
                        ConfigKeys.SRC_EXPORTER_TRACE,
                        ConfigKeys.SRC_EXPORTER_DEBUG,
                        ConfigKeys.SRC_EXPORTER_INFO,
                        ConfigKeys.SRC_EXPORTER_STATS);
    }
}
