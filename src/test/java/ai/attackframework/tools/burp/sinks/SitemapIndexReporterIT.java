package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.Optional;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
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

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String BASE_URL = OpenSearchReachable.BASE_URL;

    private static final String ITEM_URL = "https://example.com/path?q=1";
    private static final String ITEM_HOST = "example.com";
    private static final int ITEM_PORT = 443;
    private static final String ITEM_METHOD = "GET";
    private static final String ITEM_PATH = "/path?q=1";
    private static final String ITEM_QUERY = "q=1";
    private static final short ITEM_STATUS = 200;
    private static final String ITEM_REASON = "OK";

    private static String sitemapIndexName() {
        return IndexNaming.indexNameForShortName("sitemap");
    }

    private void cleanup() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
        OpenSearchClient client = OpenSearchReachable.getClient();
        try {
            client.indices().delete(new DeleteIndexRequest.Builder().index(sitemapIndexName()).build());
        } catch (Exception e) {
            Logger.logError("[SitemapIndexReporterIT] Failed to delete index during cleanup: " + sitemapIndexName(), e);
        }
    }

    @Test
    void pushNewItemsOnly_doesNotDuplicateUnchangedItemAfterBacklog() throws InterruptedException {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        try {
            createSitemapIndex();
            setRuntimeConfigForSitemapExport();
            setMockMontoyaApiWithOneSitemapItem();

            List<String> infoLines = new ArrayList<>();
            Logger.LogListener logListener = (level, message) -> {
                if ("INFO".equals(level) || "DEBUG".equals(level)) {
                    infoLines.add(message);
                }
            };
            Logger.registerListener(logListener);
            try {
                SitemapIndexReporter.start();
                SitemapIndexReporter.pushSnapshotNow();
                awaitInfoLogStartingWith(infoLines, "[SnapshotExport] Sitemap: snapshot complete: captured=");
                assertThat(awaitDocumentCount()).isEqualTo(1L);

                SitemapIndexReporter.pushNewItemsOnly();
                SitemapIndexReporter.pushNewItemsOnly();

                assertThat(awaitDocumentCount()).isEqualTo(1L);
                assertThat(infoLines.stream()
                                .anyMatch(line -> line.contains("[PeriodicExport] Sitemap: no new items")))
                        .isTrue();
            } finally {
                Logger.unregisterListener(logListener);
                SitemapIndexReporter.stop();
            }
        } finally {
            cleanup();
        }
    }

    @Test
    void pushSnapshotNow_indexesDocument_withExpectedShapeAndContent() throws InterruptedException {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        try {
            createSitemapIndex();
            setRuntimeConfigForSitemapExport();
            setMockMontoyaApiWithOneSitemapItem();

            List<String> infoLines = new ArrayList<>();
            Logger.LogListener logListener = (level, message) -> {
                if ("INFO".equals(level)) {
                    infoLines.add(message);
                }
            };
            Logger.registerListener(logListener);
            try {
                SitemapIndexReporter.start();
                SitemapIndexReporter.pushSnapshotNow();
                awaitInfoLog(infoLines, "[StartupExport] Sitemap: exporting backlog: 1 item(s).");
                awaitInfoLogStartingWith(infoLines, "[SnapshotExport] Sitemap: snapshot complete: captured=");
            } finally {
                Logger.unregisterListener(logListener);
            }

            Map<String, Object> doc = awaitFirstDocument();
            assertThat(doc).isNotNull();
            assertThat(doc).containsKeys("meta", "burp", "request", "response");
            assertThat(doc).doesNotContainKeys(
                    "request_id",
                    "source",
                    "url",
                    "host",
                    "port",
                    "protocol_transport",
                    "protocol_application",
                    "protocol_sub",
                    "method",
                    "status",
                    "reason_phrase",
                    "mime_type",
                    "content_length",
                    "path",
                    "query_string",
                    "title",
                    "param_names");

            Map<?, ?> burp = nestedMap(doc, "burp");
            assertThat(burp.containsKey("is_in_scope")).isTrue();
            assertThat(burp.containsKey("timing")).isTrue();
            assertThat(burp.containsKey("reporting_tool")).isFalse();

            Map<?, ?> request = nestedMap(doc, "request");
            assertThat(request.get("url")).isEqualTo(ITEM_URL);
            assertThat(request.get("port")).isEqualTo(ITEM_PORT);
            assertThat(request.get("method")).isEqualTo(ITEM_METHOD);
            Map<?, ?> requestProtocol = nestedMap(request, "protocol");
            assertThat(requestProtocol.get("scheme")).isEqualTo("https");
            Map<?, ?> requestPath = nestedMap(request, "path");
            assertThat(requestPath.get("with_query")).isEqualTo(ITEM_PATH);
            assertThat(requestPath.get("query")).isEqualTo(ITEM_QUERY);

            Map<?, ?> response = nestedMap(doc, "response");
            Map<?, ?> responseStatus = nestedMap(response, "status");
            assertThat(responseStatus.get("code")).isEqualTo((int) ITEM_STATUS);
            assertThat(responseStatus.get("description")).isEqualTo(ITEM_REASON);

            Map<?, ?> meta = nestedMap(doc, "meta");
            assertContainsKeys(meta, "schema_version", "extension_version", "indexed_at");
        } finally {
            cleanup();
        }
    }

    private void createSitemapIndex() {
        List<OpenSearchSink.IndexResult> results = OpenSearchReachable.createSelectedIndexes(List.of("sitemap"));
        assertThat(results).isNotEmpty();
        boolean sitemapCreated = results.stream()
                .anyMatch(r -> r.shortName().equals("sitemap") && (r.status() == OpenSearchSink.IndexResult.Status.CREATED || r.status() == OpenSearchSink.IndexResult.Status.EXISTS));
        assertThat(sitemapCreated).as("sitemap index created or exists").isTrue();
    }

    private void setRuntimeConfigForSitemapExport() {
        ai.attackframework.tools.burp.testutils.OpenSearchTestConfig config = ai.attackframework.tools.burp.testutils.OpenSearchTestConfig.get();
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, BASE_URL, config.username(), config.password(), false);
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SITEMAP),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks,
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
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
        when(request.pathWithoutQuery()).thenReturn("/path");
        when(request.query()).thenReturn(ITEM_QUERY);
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.parameters(HttpParameterType.URL)).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);
        burp.api.montoya.core.ByteArray requestBytes = mockByteArray(
                "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
        when(request.toByteArray()).thenReturn(requestBytes);

        when(response.statusCode()).thenReturn(ITEM_STATUS);
        when(response.reasonPhrase()).thenReturn(ITEM_REASON);
        when(response.mimeType()).thenReturn(burp.api.montoya.http.message.MimeType.HTML);
        when(response.statedMimeType()).thenReturn(burp.api.montoya.http.message.MimeType.HTML);
        when(response.inferredMimeType()).thenReturn(burp.api.montoya.http.message.MimeType.HTML);
        when(response.httpVersion()).thenReturn("HTTP/1.1");
        when(response.headers()).thenReturn(List.of());
        when(response.body()).thenReturn(null);
        when(response.markers()).thenReturn(List.of());
        burp.api.montoya.core.ByteArray responseBytes = mockByteArray(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        when(response.toByteArray()).thenReturn(responseBytes);

        when(httpService.host()).thenReturn(ITEM_HOST);
        when(httpService.port()).thenReturn(ITEM_PORT);
        when(httpService.secure()).thenReturn(true);

        MontoyaApiProvider.set(api);
    }

    private long awaitDocumentCount() throws InterruptedException {
        OpenSearchClient client = OpenSearchReachable.getClient();
        int maxAttempts = 10;
        for (int i = 0; i < maxAttempts; i++) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(sitemapIndexName()).build());
                long count = client.count(c -> c.index(sitemapIndexName())).count();
                if (count > 0 || i == maxAttempts - 1) {
                    return count;
                }
            } catch (Exception e) {
                if (i == maxAttempts - 1) {
                    throw new AssertionError("Count failed: " + e.getMessage(), e);
                }
            }
            Thread.sleep(300);
        }
        return 0L;
    }

    private Map<String, Object> awaitFirstDocument() {
        OpenSearchClient client = OpenSearchReachable.getClient();
        SearchRequest req = new SearchRequest.Builder()
                .index(sitemapIndexName())
                .size(1)
                .build();
        int maxAttempts = 5;
        for (int i = 0; i < maxAttempts; i++) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(sitemapIndexName()).build());
            } catch (Exception ignored) {
                // best-effort refresh
            }
            try {
                SearchResponse<JsonNode> resp = client.search(req, JsonNode.class);
                List<?> hits = resp.hits().hits();
                if (!hits.isEmpty()) {
                    JsonNode source = resp.hits().hits().get(0).source();
                    if (source != null) {
                        return JSON.convertValue(source, new TypeReference<Map<String, Object>>() { });
                    }
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

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        Object value = parent.get(key);
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
    }

    private static void assertContainsKeys(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            assertThat(map.containsKey(key)).isTrue();
        }
    }

    private static burp.api.montoya.core.ByteArray mockByteArray(String raw) {
        burp.api.montoya.core.ByteArray bytes = mock(burp.api.montoya.core.ByteArray.class);
        when(bytes.getBytes()).thenReturn(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return bytes;
    }

    private static void awaitInfoLog(List<String> infoLines, String expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (infoLines.contains(expected)) {
                return;
            }
            Thread.sleep(20);
        }
        assertThat(infoLines).contains(expected);
    }

    private static void awaitInfoLogStartingWith(List<String> infoLines, String prefix) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (infoLines.stream().anyMatch(line -> line.startsWith(prefix))) {
                return;
            }
            Thread.sleep(20);
        }
        assertThat(infoLines).anyMatch(line -> line.startsWith(prefix));
    }
}
