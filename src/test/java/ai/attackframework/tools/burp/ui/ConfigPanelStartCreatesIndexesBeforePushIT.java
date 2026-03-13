package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.mapping.Property;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.GetMappingRequest;
import org.opensearch.client.opensearch.indices.GetMappingResponse;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import static org.assertj.core.api.Assertions.assertThat;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.testutils.OpenSearchTestConfig;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration test: when Start is clicked in ConfigPanel, indexes are created explicitly
 * (via createSelectedIndexes) before any documents are pushed. Uses real OpenSearch.
 * Verifies the findings index exists with explicit mapping (e.g. request_responses nested)
 * and has at least one document after Start.
 */
@Tag("integration")
class ConfigPanelStartCreatesIndexesBeforePushIT {

    private static final String BASE_URL = OpenSearchReachable.BASE_URL;
    private static final String FINDINGS_INDEX = IndexNaming.INDEX_PREFIX + "-findings";

    private static final class TestUi implements ConfigController.Ui {
        @Override public void onFileStatus(String m) { }
        @Override public void onOpenSearchStatus(String m) { }
        @Override public void onControlStatus(String m) { }
    }

    private ConfigPanel panel;

    @BeforeEach
    void setup() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        deleteFindingsIndex();

        MontoyaApiProvider.set(mockMontoyaApiWithOneIssue());
        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_FINDINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, BASE_URL, config.username(), config.password(), false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel p = new ConfigPanel(new ConfigController(new TestUi()));
            if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                p.setSize(1000, 700);
            }
            p.doLayout();
            JTextField urlField = get(p, "openSearchUrlField");
            urlField.setText(BASE_URL);
            JCheckBox osCheckbox = get(p, "openSearchSinkCheckbox");
            if (!osCheckbox.isSelected()) osCheckbox.doClick();
            JCheckBox issuesCheckbox = get(p, "issuesCheckbox");
            issuesCheckbox.setEnabled(true);
            if (!issuesCheckbox.isSelected()) issuesCheckbox.doClick();
            javax.swing.JComboBox<?> authCombo = get(p, "openSearchAuthTypeCombo");
            if (authCombo != null && config.username() != null && !config.username().isBlank()) {
                authCombo.setSelectedIndex(1);
                JTextField userField = get(p, "openSearchUserField");
                JTextField passField = get(p, "openSearchPasswordField");
                if (userField != null) userField.setText(config.username());
                if (passField != null) passField.setText(config.password() != null ? config.password() : "");
            }
            ref.set(p);
        });
        panel = ref.get();
    }

    @AfterEach
    void tearDown() {
        RuntimeConfig.setExportRunning(false);
        MontoyaApiProvider.set(null);
        deleteFindingsIndex();
    }

    @Test
    void start_click_createsFindingsIndexWithExplicitMapping_beforeDocsPushed() throws Exception {
        JButton startStop = findByName(panel, "control.startStop", JButton.class);
        assertThat(startStop).as("Start button").isNotNull();
        assertThat(startStop.getText()).isEqualTo("Start");

        SwingUtilities.invokeAndWait(startStop::doClick);
        SwingUtilities.invokeAndWait(() -> { /* flush EDT so deferred start action runs */ });

        awaitFindingsIndexWithAtLeastOneDoc();

        OpenSearchClient client = OpenSearchReachable.getClient();
        GetMappingResponse mappingResp = client.indices()
                .getMapping(new GetMappingRequest.Builder().index(FINDINGS_INDEX).build());
        assertThat(mappingResp.result()).containsKey(FINDINGS_INDEX);

        var indexMapping = mappingResp.result().get(FINDINGS_INDEX);
        assertThat(indexMapping).isNotNull();
        assertThat(indexMapping.mappings()).isNotNull();
        var properties = indexMapping.mappings().properties();
        assertThat(properties).as("explicit mapping").containsKey("request_responses");
        Property reqRespProp = properties.get("request_responses");
        assertThat(reqRespProp).isNotNull();
    }

    private static MontoyaApi mockMontoyaApiWithOneIssue() {
        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        Scope scope = mock(Scope.class);
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        HttpService httpService = mock(HttpService.class);
        BurpSuite burpSuite = mock(BurpSuite.class);
        Version version = mock(Version.class);

        when(api.siteMap()).thenReturn(siteMap);
        when(api.scope()).thenReturn(scope);
        when(api.burpSuite()).thenReturn(burpSuite);
        when(burpSuite.version()).thenReturn(version);
        when(version.edition()).thenReturn(BurpSuiteEdition.COMMUNITY_EDITION);
        when(scope.isInScope(anyString())).thenReturn(true);
        when(siteMap.issues()).thenReturn(List.of(issue));

        when(issue.name()).thenReturn("Test issue");
        when(issue.baseUrl()).thenReturn("https://example.com/");
        when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.httpService()).thenReturn(httpService);
        when(issue.detail()).thenReturn("Detail");
        when(issue.remediation()).thenReturn("Remediation");
        when(issue.definition()).thenReturn(definition);
        when(issue.requestResponses()).thenReturn(List.of());

        when(httpService.host()).thenReturn("example.com");
        when(httpService.port()).thenReturn(443);
        when(httpService.secure()).thenReturn(true);

        when(definition.typeIndex()).thenReturn(0);
        when(definition.typicalSeverity()).thenReturn(AuditIssueSeverity.HIGH);
        when(definition.background()).thenReturn("Background");
        when(definition.remediation()).thenReturn("Remediation");

        return api;
    }

    private void awaitFindingsIndexWithAtLeastOneDoc() {
        OpenSearchClient client = OpenSearchReachable.getClient();
        long deadline = System.currentTimeMillis() + 30_000;
        while (System.currentTimeMillis() < deadline) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(FINDINGS_INDEX).build());
                SearchResponse<?> resp = client.search(
                        new SearchRequest.Builder().index(FINDINGS_INDEX).size(1).build(),
                        Object.class);
                if (resp.hits().hits().size() >= 1) {
                    return;
                }
            } catch (Exception ignored) {
                // index may not exist yet
            }
            LockSupport.parkNanos(200_000_000L);
        }
        throw new AssertionError("Findings index did not get at least one document within 30s");
    }

    private static void deleteFindingsIndex() {
        try {
            OpenSearchClient client = OpenSearchReachable.getClient();
            client.indices().delete(new DeleteIndexRequest.Builder().index(FINDINGS_INDEX).build());
        } catch (Exception ignored) {
            // index may not exist
        }
    }

    @SuppressWarnings("unchecked")
    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        if (type.isInstance(root) && name.equals(root.getName())) {
            return (T) root;
        }
        for (Component c : root.getComponents()) {
            if (c instanceof Container cont) {
                T found = findByName(cont, name, type);
                if (found != null) return found;
            }
            if (type.isInstance(c) && name.equals(c.getName())) {
                return (T) c;
            }
        }
        return null;
    }
}
