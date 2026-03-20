package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class JsonSinksOmissionTest {

    private static final String FILES_ROOT = "/path/to/directory";
    private static final String OS_URL = "https://opensearch.url:9200";

    @Test
    void build_omits_blank_sinks_fields() throws IOException {
        var state = new ConfigState.State(
                null, "all", null,
                new ConfigState.Sinks(false, "", false, "", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.filesPath()).isNull();
        assertThat(cfg.openSearchUrl()).isNull();
    }

    @Test
    void build_includes_nonEmpty_sinks_fields() throws IOException {
        var state = new ConfigState.State(
                null, "all", null,
                new ConfigState.Sinks(true, FILES_ROOT, true, OS_URL, "admin", "admin", false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        String json = ConfigJsonMapper.build(state);
        assertThat(json).doesNotContain("openSearchUser");
        assertThat(json).doesNotContain("openSearchPassword");

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.filesPath()).isEqualTo(FILES_ROOT);
        assertThat(cfg.openSearchUrl()).isEqualTo(OS_URL);
        assertThat(cfg.openSearchUser()).isBlank();
        assertThat(cfg.openSearchPassword()).isBlank();
    }

    @Test
    void parse_blank_strings_are_treated_as_null() throws IOException {
        String json = """
            {
              "sinks": {
                "files": "",
                "openSearch": ""
              }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.filesPath()).isNull();
        assertThat(cfg.openSearchUrl()).isNull();
    }

    @Test
    void parse_legacy_openSearch_credentials_are_ignored() throws IOException {
        String json = """
            {
              "sinks": {
                "openSearch": "https://opensearch.url:9200",
                "openSearchUser": "admin",
                "openSearchPassword": "secret"
              }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.openSearchUrl()).isEqualTo(OS_URL);
        assertThat(cfg.openSearchUser()).isBlank();
        assertThat(cfg.openSearchPassword()).isBlank();
    }
}
