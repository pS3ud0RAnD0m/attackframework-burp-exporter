package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JsonTypedRoundTripTest {

    @Test
    void build_and_parse_typed_custom_scope_preserves_order_and_kinds() throws IOException {
        List<String> sources = List.of("settings", "sitemap", "findings", "traffic");
        String scopeType = "custom";
        List<String> values = List.of("^rx1$", "aaa", "bbb", "^rx2$");
        List<String> kinds  = List.of("regex", "string", "string", "regex");

        String json = Json.buildConfigJsonTyped(
                sources, scopeType, values, kinds,
                true, "/tmp/dir",
                true, "http://os:9200"
        );

        // Quick sanity on top-level ordering (version first).
        assertThat(json.indexOf("\"version\"")).isLessThan(json.indexOf("\"dataSources\""));

        Json.ImportedConfig parsed = Json.parseConfigJson(json);

        assertThat(parsed.dataSources).containsExactlyElementsOf(sources);
        assertThat(parsed.scopeType).isEqualTo("custom");
        assertThat(parsed.scopeRegexes).containsExactlyElementsOf(values);
        assertThat(parsed.scopeKinds).containsExactlyElementsOf(kinds);
        assertThat(parsed.filesPath).isEqualTo("/tmp/dir");
        assertThat(parsed.openSearchUrl).isEqualTo("http://os:9200");
    }

    @Test
    void build_all_scope_sets_flag_only() throws IOException {
        String json = Json.buildConfigJsonTyped(
                List.of("settings"), "all", null, null,
                false, null, false, null
        );
        Json.ImportedConfig parsed = Json.parseConfigJson(json);
        assertThat(parsed.scopeType).isEqualTo("all");
        assertThat(parsed.scopeRegexes).isEmpty();
        assertThat(parsed.scopeKinds).isNull();
    }

    @Test
    void build_burp_scope_sets_flag_only() throws IOException {
        String json = Json.buildConfigJsonTyped(
                List.of("settings"), "burp", null, null,
                false, null, false, null
        );
        Json.ImportedConfig parsed = Json.parseConfigJson(json);
        assertThat(parsed.scopeType).isEqualTo("burp");
        assertThat(parsed.scopeRegexes).isEmpty();
        assertThat(parsed.scopeKinds).isNull();
    }
}
