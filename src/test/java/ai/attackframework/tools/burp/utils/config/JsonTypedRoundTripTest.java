package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JsonTypedRoundTripTest {

    @Test
    void build_and_parse_typed_custom_scope_preserves_order_and_kinds() throws IOException {
        List<String> sources = List.of("settings", "traffic");
        List<String> values = List.of("x", "y");
        List<String> kinds = List.of("regex", "string");

        String json = Json.buildConfigJsonTyped(
                sources, "custom", values, kinds,
                true, "/path/to/directory", true, "http://opensearch.url:9200"
        );

        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(parsed.dataSources()).containsExactlyElementsOf(sources);
        assertThat(parsed.scopeType()).isEqualTo("custom");
        assertThat(parsed.scopeRegexes()).containsExactlyElementsOf(values);
        assertThat(parsed.filesPath()).isEqualTo("/path/to/directory");
        assertThat(parsed.openSearchUrl()).isEqualTo("http://opensearch.url:9200");
    }

    @Test
    void build_all_scope_sets_flag_only() throws IOException {
        String json = Json.buildConfigJsonTyped(
                List.of("settings"), "all", null, null,
                false, null, false, null
        );

        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(parsed.scopeType()).isEqualTo("all");
        assertThat(parsed.scopeRegexes()).isEmpty();
    }

    @Test
    void build_burp_scope_sets_flag_only() throws IOException {
        String json = Json.buildConfigJsonTyped(
                List.of("traffic"), "burp", null, null,
                false, null, false, null
        );

        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(parsed.scopeType()).isEqualTo("burp");
        assertThat(parsed.scopeRegexes()).isEmpty();
    }
}
