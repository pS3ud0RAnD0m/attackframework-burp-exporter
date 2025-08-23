package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class JsonTypedObjectOrderAgnosticTest {

    @Test
    void parse_typed_object_shape_handles_arbitrary_field_order() throws IOException {
        String json = """
            {
              "scope": {
                "custom": ["bbb", "^foo$", "aaa", "bar.*"],
                "customTypes": ["string", "regex", "string", "regex"],
                "type": "custom"
              }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(json);

        assertThat(cfg.scopeType()).isEqualTo("custom");
        assertThat(cfg.scopeRegexes()).containsExactly("bbb", "^foo$", "aaa", "bar.*");
    }
}
