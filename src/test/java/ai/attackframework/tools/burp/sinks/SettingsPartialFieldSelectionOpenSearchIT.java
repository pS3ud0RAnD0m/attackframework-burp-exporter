package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.awaitSingleIndexedDocument;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.nestedMap;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.pushOneDocument;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

@Tag("integration")
class SettingsPartialFieldSelectionOpenSearchIT {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        deleteIndex("settings");
    }

    @Test
    void partialSettingsFieldSelection_indexesSparseDocument() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        createIndex("settings");

        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of("settings", Set.of("burp.project_id", "project")));

        Map<String, Object> built = new LinkedHashMap<>();
        built.put("burp", Map.of("project_id", "it-partial-project", "version", "2026.4"));
        built.put("meta", Map.of("schema_version", "1"));
        built.put("project", Map.of("project_options", Map.of("test_key", "project_value")));
        built.put("user", Map.of("user_options", Map.of("test_key", "user_value")));

        pushOneDocument("settings", built, state);
        Map<String, Object> stored = awaitSingleIndexedDocument("settings");

        assertThat(stored).containsKeys("meta", "burp", "project");
        assertThat(stored).doesNotContainKey("user");
        assertThat(nestedMap(stored, "burp").get("project_id")).isEqualTo("it-partial-project");
        assertThat(nestedMap(stored, "burp").containsKey("version")).isFalse();
        assertThat(nestedMap(stored, "project").get("project_options"))
                .isEqualTo(Map.of("test_key", "project_value"));
    }
}
