package ai.attackframework.tools.burp.sinks;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;

/**
 * Integration test: {@link SitemapIndexReporter} pushes a document to the
 * sitemap index when export is running and Burp API supplies sitemap items.
 * Uses real OpenSearch at {@value #BASE_URL}; mocks MontoyaApi and
 * siteMap().requestResponses(). Verifies document shape after round-trip.
 */
@Tag("integration")
class SitemapIndexReporterIT {

    private static final String BASE_URL = "http://opensearch.url:9200";
    private static final String SITEMAP_INDEX = IndexNaming.INDEX_PREFIX + "-sitemap";

    private static final String ITEM_URL = "https://example.com/path?q=1";
    private static final String ITEM_HOST = "example.com";
    private static final int ITEM_PORT = 443;
    private static final String ITEM_METHOD = "GET";
    private static final String ITEM_PATH = "/path?q=1";
    private static final String ITEM_QUERY = "q=1";
    private static final short ITEM_STATUS = 200;
    private static final String ITEM_REASON = "OK";

    @BeforeEach
    void assumeOpenSearchReachable() {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");
    }

    @AfterEach
    void cleanup() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        try {
            client.indices().delete(new DeleteIndexRequest.Builder().index(SITEMAP_INDEX).build());
        } catch (Exception e) {
            Logger.logError("[SitemapIndexReporterIT] Failed to delete index during cleanup: " + SITEMAP_INDEX, e);
        }
    }

    @Test
    void pushSnapshotNow_indexesDocument_withExpectedShapeAndContent() {
        createSitemapIndex();
        setRuntimeConfigForSitemapExport();
        setMockMontoyaApiWithOneSitemapItem();

        SitemapIndexReporter.start();
        SitemapIndexReporter.pushSnapshotNow();

        Map<String, Object> doc = awaitFirstDocument();
        assertThat(doc).isNotNull();
        assertThat(doc).containsKey("url");
        assertThat(doc).containsKey("host");
        assertThat(doc).containsKey("port");
        assertThat(doc).containsKey("protocol_transport");
        assertThat(doc).containsKey("method");
        assertThat(doc).containsKey("status_code");
        assertThat(doc).containsKey("request_id");
        assertThat(doc).containsKey("document_meta");
        assertThat(doc).containsKey("source");
        assertThat(doc).containsKey("path");
        assertThat(doc).containsKey("status_reason");

        assertThat(doc.get("url")).isEqualTo(ITEM_URL);
        assertThat(doc.get("host")).isEqualTo(ITEM_HOST);
        assertThat(doc.get("port")).isEqualTo(ITEM_PORT);
        assertThat(doc.get("protocol_transport")).isEqualTo("https");
        assertThat(doc.get("method")).isEqualTo(ITEM_METHOD);
        assertThat(doc.get("status_code")).isEqualTo((int) ITEM_STATUS);
        assertThat(doc.get("status_reason")).isEqualTo(ITEM_REASON);
        assertThat(doc.get("path")).isEqualTo(ITEM_PATH);
        assertThat(doc.get("source")).isEqualTo("burp-exporter");

        @SuppressWarnings("unchecked")
        Map<String, Object> documentMeta = (Map<String, Object>) doc.get("document_meta");
        assertThat(documentMeta).isNotNull()
                .containsKey("schema_version")
                .containsKey("extension_version")
                .containsKey("indexed_at");
    }

    private void createSitemapIndex() {
        List<OpenSearchSink.IndexResult> results = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("sitemap"));
        assertThat(results).isNotEmpty();
        boolean sitemapCreated = results.stream()
                .anyMatch(r -> r.shortName().equals("sitemap") && (r.status() == OpenSearchSink.IndexResult.Status.CREATED || r.status() == OpenSearchSink.IndexResult.Status.EXISTS));
        assertThat(sitemapCreated).as("sitemap index created or exists").isTrue();
    }

    private void setRuntimeConfigForSitemapExport() {
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, BASE_URL);
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SITEMAP),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks);
        RuntimeConfig.updateState(state);
        RuntimeConfig.setExportRunning(true);
    }

    private void setMockMontoyaApiWithOneSitemapItem() {
        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        Scope scope = mock(Scope.class);
        HttpRequestResponse item = mock(HttpRequestResponse.class);
        HttpRequest request = mock(HttpRequest.class);
        HttpResponse response = mock(HttpResponse.class);
        HttpService httpService = mock(HttpService.class);

        when(api.siteMap()).thenReturn(siteMap);
        when(api.scope()).thenReturn(scope);
        when(scope.isInScope(anyString())).thenReturn(true);
        when(siteMap.requestResponses()).thenReturn(List.of(item));

        when(item.request()).thenReturn(request);
        when(item.response()).thenReturn(response);
        when(item.hasResponse()).thenReturn(true);
        when(item.httpService()).thenReturn(httpService);
        when(item.timingData()).thenReturn(Optional.empty());

        when(request.url()).thenReturn(ITEM_URL);
        when(request.method()).thenReturn(ITEM_METHOD);
        when(request.path()).thenReturn(ITEM_PATH);
        when(request.query()).thenReturn(ITEM_QUERY);
        when(request.parameters()).thenReturn(List.of());

        when(response.statusCode()).thenReturn(ITEM_STATUS);
        when(response.reasonPhrase()).thenReturn(ITEM_REASON);
        when(response.mimeType()).thenReturn(burp.api.montoya.http.message.MimeType.HTML);
        when(response.body()).thenReturn(null);

        when(httpService.host()).thenReturn(ITEM_HOST);
        when(httpService.port()).thenReturn(ITEM_PORT);
        when(httpService.secure()).thenReturn(true);

        MontoyaApiProvider.set(api);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> awaitFirstDocument() {
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        SearchRequest req = new SearchRequest.Builder()
                .index(SITEMAP_INDEX)
                .size(1)
                .build();
        int maxAttempts = 5;
        for (int i = 0; i < maxAttempts; i++) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(SITEMAP_INDEX).build());
            } catch (Exception ignored) {
                // best-effort refresh
            }
            try {
                SearchResponse<Map<String, Object>> resp = client.search(req, (Class<Map<String, Object>>) (Class<?>) Map.class);
                List<?> hits = resp.hits().hits();
                if (!hits.isEmpty()) {
                    return (Map<String, Object>) resp.hits().hits().get(0).source();
                }
            } catch (Exception e) {
                throw new AssertionError("Search failed: " + e.getMessage(), e);
            }
            if (i < maxAttempts - 1) {
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError("Interrupted while awaiting document", e);
                }
            }
        }
        throw new AssertionError("at least one document indexed (after " + maxAttempts + " attempts)");
    }
}
