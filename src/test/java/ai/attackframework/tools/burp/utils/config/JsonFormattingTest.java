package ai.attackframework.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;

class JsonFormattingTest {

    @Test
    void build_outputsPrettyPrintedJson() throws IOException {
        var state = new ConfigState.State(
                List.of("settings", "traffic"),
                "custom",
                List.of(
                        new ConfigState.ScopeEntry("^.*acme\\.com$", ConfigState.Kind.REGEX),
                        new ConfigState.ScopeEntry("api.acme.local", ConfigState.Kind.STRING)
                ),
                new ConfigState.Sinks(
                        true,
                        "/tmp/export",
                        true,
                        "https://opensearch.url:9200",
                        "",
                        "",
                        true
                ),
                List.of(ConfigKeys.SRC_SETTINGS_PROJECT),
                List.of("PROXY", "REPEATER"),
                List.of("HIGH", "CRITICAL"),
                null
        );

        String json = ConfigJsonMapper.build(state);

        assertThat(json)
                .contains("\n")
                .contains("\n  \"dataSources\"")
                .contains("\n  \"scope\"")
                .contains("\n  \"sinks\"")
                .endsWith("\n}");
    }
}
