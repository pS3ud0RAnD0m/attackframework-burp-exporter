package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class JsonTypedObjectOrderAgnosticTest {

    @Test
    void parse_typed_object_shape_handles_arbitrary_field_order() throws IOException {
        String json = """
            {
              "dataSources": ["settings","sitemap"],
              "scope": {
                "custom": {
                  "string2": "bbb",
                  "regex1": "^foo$",
                  "string1": "aaa",
                  "regex2": "bar.*"
                }
              },
              "sinks": { "files": "/tmp/x" }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(json);

        assertThat(cfg.scopeType).isEqualTo("custom");
        // Values captured in the order they appear in the JSON (jackson preserves insertion order)
        assertThat(cfg.scopeRegexes).containsExactly("bbb", "^foo$", "aaa", "bar.*");
        assertThat(cfg.scopeKinds).containsExactly("string", "regex", "string", "regex");
    }
}
