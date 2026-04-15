package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.core.Version;

/**
 * Community edition must not export Scanner / Burp AI traffic even when those
 * tool types appear in persisted config; {@link OpenSearchTrafficHandler} gates
 * on {@link RuntimeConfig#isTrafficToolTypeEnabled(String)}.
 */
class OpenSearchTrafficHandlerCommunityEditionGatingTest {

    private final ConfigState.State previousState = RuntimeConfig.getState();
    private final MontoyaApi previousApi = MontoyaApiProvider.get();

    private void reset() {
        RuntimeConfig.updateState(previousState);
        MontoyaApiProvider.set(previousApi);
    }

    @Test
    void shouldExportTrafficByToolSource_blocksScannerAndBurpAi_whenCommunityStripsToolTypes() {
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            BurpSuite burpSuite = mock(BurpSuite.class);
            Version version = mock(Version.class);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(burpSuite.version()).thenReturn(version);
            when(version.edition()).thenReturn(BurpSuiteEdition.COMMUNITY_EDITION);
            MontoyaApiProvider.set(api);

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy", "scanner", "burp_ai"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));

            assertThat(RuntimeConfig.getState().trafficToolTypes()).containsExactly("proxy");

            assertThat((Boolean) callStatic(OpenSearchTrafficHandler.class, "shouldExportTrafficByToolSource", ToolType.SCANNER))
                    .isFalse();
            assertThat((Boolean) callStatic(OpenSearchTrafficHandler.class, "shouldExportTrafficByToolSource", ToolType.BURP_AI))
                    .isFalse();
            assertThat((Boolean) callStatic(OpenSearchTrafficHandler.class, "shouldExportTrafficByToolSource", ToolType.PROXY))
                    .isTrue();
        } finally {
            reset();
        }
    }
}
