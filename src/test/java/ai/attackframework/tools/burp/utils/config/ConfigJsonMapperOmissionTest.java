package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the mapper omits blank/whitespace-only custom entries when building JSON.
 */
class ConfigJsonMapperOmissionTest {

    @Test
    void build_omits_blank_custom_entries() throws IOException {
        // custom entries include blanks that should be omitted
        var state = new ConfigState.State(
                null, "custom",
                List.of(
                        new ConfigState.ScopeEntry("",     ConfigState.Kind.REGEX),
                        new ConfigState.ScopeEntry("   ",  ConfigState.Kind.STRING),
                        new ConfigState.ScopeEntry("\t",   ConfigState.Kind.REGEX),
                        new ConfigState.ScopeEntry("x",    ConfigState.Kind.REGEX)
                ),
                new ConfigState.Sinks(false, null, false, null),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES
        );

        String json = ConfigJsonMapper.build(state);
        Json.ImportedConfig cfg = Json.parseConfigJson(json);

        // Only the non-blank entry remains; order preserved for the remaining items
        assertThat(cfg.scopeType()).isEqualTo("custom");
        assertThat(cfg.scopeRegexes()).containsExactly("x");
    }
}
