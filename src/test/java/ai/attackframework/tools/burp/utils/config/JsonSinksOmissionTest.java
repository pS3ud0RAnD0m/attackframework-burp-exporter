package ai.attackframework.tools.burp.utils.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JsonSinksOmissionTest {

    private static final ObjectMapper M = new ObjectMapper();
    private static final String FILES_ROOT = "/path/to/directory";
    private static final String OS_URL = "http://opensearch.url:9200";

    @Test
    void build_omits_blank_sinks_fields() throws Exception {
        String json = Json.buildConfigJsonTyped(
                List.of("settings"), "all", null, null,
                false, "", false, ""
        );

        JsonNode root = M.readTree(json);
        JsonNode sinks = root.path("sinks");
        assertThat(sinks.isObject()).isTrue();
        assertThat(sinks.has("files")).isFalse();
        assertThat(sinks.has("openSearch")).isFalse();

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.filesPath).isNull();
        assertThat(cfg.openSearchUrl).isNull();
    }

    @Test
    void build_includes_nonEmpty_sinks_fields() throws Exception {
        String json = Json.buildConfigJsonTyped(
                List.of("settings"), "all", null, null,
                true, FILES_ROOT, true, OS_URL
        );

        JsonNode root = M.readTree(json);
        JsonNode sinks = root.path("sinks");
        assertThat(sinks.get("files").asText()).isEqualTo(FILES_ROOT);
        assertThat(sinks.get("openSearch").asText()).isEqualTo(OS_URL);

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.filesPath).isEqualTo(FILES_ROOT);
        assertThat(cfg.openSearchUrl).isEqualTo(OS_URL);
    }

    @Test
    void parse_blank_strings_are_treated_as_null() throws Exception {
        String json = """
            {
              "dataSources": ["settings"],
              "scope": { "all": true },
              "sinks": { "files": "", "openSearch": "   " }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        assertThat(cfg.filesPath).isNull();
        assertThat(cfg.openSearchUrl).isNull();
    }
}
