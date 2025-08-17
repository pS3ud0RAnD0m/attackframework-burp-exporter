package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class JsonLegacyCompatibilityTest {

    @Test
    void parse_legacy_array_only_treats_all_as_untyped_and_preserves_order() throws IOException {
        String json = """
            {
              "dataSources": ["settings"],
              "scope": {
                "custom": ["^a$", "b", "^c$"]
              },
              "sinks": {}
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(json);

        assertThat(cfg.scopeType).isEqualTo("custom");
        assertThat(cfg.scopeRegexes).containsExactly("^a$", "b", "^c$");
        // legacy array without customTypes -> kinds remain null
        assertThat(cfg.scopeKinds).isNull();
    }

    @Test
    void parse_typed_arrays_uses_customTypes_and_preserves_order() throws IOException {
        String json = """
            {
              "dataSources": ["settings"],
              "scope": {
                "custom": ["^a$", "b", "^c$"],
                "customTypes": ["regex", "string", "regex"]
              },
              "sinks": {}
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(json);

        assertThat(cfg.scopeType).isEqualTo("custom");
        assertThat(cfg.scopeRegexes).containsExactly("^a$", "b", "^c$");
        assertThat(cfg.scopeKinds).containsExactly("regex", "string", "regex");
    }

    @Test
    void parse_typed_arrays_ignores_mismatched_customTypes_length() throws IOException {
        String json = """
            {
              "scope": {
                "custom": ["x", "y"],
                "customTypes": ["regex"]
              }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(json);

        assertThat(cfg.scopeType).isEqualTo("custom");
        assertThat(cfg.scopeRegexes).containsExactly("x", "y");
        // size mismatch -> kinds left null per implementation
        assertThat(cfg.scopeKinds).isNull();
    }
}
