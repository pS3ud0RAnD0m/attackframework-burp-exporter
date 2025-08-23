package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JsonLegacyCompatibilityTest {

    @Test
    void parse_legacy_array_only_treats_all_as_untyped_and_preserves_order() throws Exception {
        String legacyJson = """
            {
              "scope": {
                "custom": ["^a$", "b", "^c$"]
              }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(legacyJson);
        assertThat(cfg.scopeType()).isEqualTo("custom");
        assertThat(cfg.scopeRegexes()).containsExactly("^a$", "b", "^c$");
    }

    @Test
    void parse_typed_arrays_uses_customTypes_and_preserves_order() throws Exception {
        String legacyJson = """
            {
              "scope": {
                "custom": ["^a$", "b", "^c$"],
                "customTypes": ["regex", "string", "regex"]
              }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(legacyJson);
        assertThat(cfg.scopeType()).isEqualTo("custom");
        assertThat(cfg.scopeRegexes()).containsExactly("^a$", "b", "^c$");
    }

    @Test
    void parse_typed_arrays_ignores_mismatched_customTypes_length() throws Exception {
        String legacyJson = """
            {
              "scope": {
                "custom": ["x", "y"],
                "customTypes": ["regex"]
              }
            }
            """;

        Json.ImportedConfig cfg = Json.parseConfigJson(legacyJson);
        assertThat(cfg.scopeType()).isEqualTo("custom");
        assertThat(cfg.scopeRegexes()).containsExactly("x", "y");
    }
}
