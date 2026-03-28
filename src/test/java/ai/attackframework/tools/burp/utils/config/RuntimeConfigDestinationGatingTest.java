package ai.attackframework.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class RuntimeConfigDestinationGatingTest {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    @SuppressWarnings("unused")
    void restoreRuntimeState() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void openSearchUrl_returnsBlank_whenDestinationDisabledEvenIfUrlIsSaved() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(true, "/path/to/directory", false, true,
                        false, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        ));

        assertThat(RuntimeConfig.isAnyFileExportEnabled()).isTrue();
        assertThat(RuntimeConfig.isAnySinkEnabled()).isTrue();
        assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
        assertThat(RuntimeConfig.openSearchUrl()).isEmpty();
    }

    @Test
    void isOpenSearchTrafficEnabled_isFalse_whenOnlyFileTrafficExportIsConfigured() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(true, "/path/to/directory", false, true,
                        false, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("PROXY"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        ));

        assertThat(RuntimeConfig.isAnyTrafficExportEnabled()).isTrue();
        assertThat(RuntimeConfig.isOpenSearchTrafficEnabled()).isFalse();
    }

    @Test
    void isOpenSearchExportEnabled_isTrue_whenDestinationAndUrlAreConfigured() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        ));

        assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isTrue();
        assertThat(RuntimeConfig.openSearchUrl()).isEqualTo("https://opensearch.url:9200");
    }
}
