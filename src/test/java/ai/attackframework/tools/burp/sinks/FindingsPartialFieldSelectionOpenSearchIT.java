package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.awaitDocumentByExportId;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.nestedMap;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static ai.attackframework.tools.burp.testutils.PartialFieldOpenSearchTestSupport.pushOneDocument;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Verifies partially filtered findings documents index on the configured OpenSearch test cluster.
 */
@Tag("integration")
class FindingsPartialFieldSelectionOpenSearchIT {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        deleteIndex("findings");
    }

    @Test
    void partialFindingsFieldSelection_indexesSparseNestedShape() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        createIndex("findings");

        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_FINDINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of("findings", Set.of("issue.name", "target.url")));

        AuditIssue issue = mock(AuditIssue.class);
        HttpService service = mock(HttpService.class);
        when(issue.name()).thenReturn("SQL injection");
        when(issue.baseUrl()).thenReturn("https://example.com/page");
        when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.detail()).thenReturn("detail");
        when(issue.remediation()).thenReturn("fix");
        when(issue.httpService()).thenReturn(service);
        when(issue.requestResponses()).thenReturn(List.of());
        when(issue.definition()).thenReturn(null);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);

        Map<String, Object> built = FindingsIndexReporter.buildFindingDoc(issue);
        PreparedExportDocument prepared = pushOneDocument("findings", built, state);

        Map<String, Object> stored = awaitDocumentByExportId("findings", prepared.exportId());
        assertThat(stored).containsKeys("meta", "issue", "target");
        assertThat(stored).doesNotContainKeys("burp", "requests_responses", "collaborator");
        assertThat(nestedMap(stored, "issue").get("name")).isEqualTo("SQL injection");
        assertThat(nestedMap(stored, "target").get("url")).isEqualTo("https://example.com/page");
        assertThat(nestedMap(stored, "issue").containsKey("severity")).isFalse();
    }
}
