package ai.attackframework.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.attackframework.tools.burp.sinks.FileExportService;
import ai.attackframework.tools.burp.sinks.OpenSearchCleanupIT;
import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.ExportDocumentIdentity;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

/**
 * Verifies that exported NDJSON files can be re-imported idempotently into OpenSearch.
 *
 * <p>The same exported file is imported twice into the same target index. Because the file uses
 * the shared stable export ID in its bulk action metadata, the second import should update in
 * place rather than increasing document count.</p>
 */
@Tag("integration")
class FileExportReimportIT {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    @SuppressWarnings("unused")
    void tearDown() {
        RuntimeConfig.updateState(previous);
        FileExportService.resetForTests();
        OpenSearchCleanupIT.deleteAttackFrameworkIndexesNow();
    }

    @Test
    void exportedNdjson_canBeImportedTwice_withoutIncreasingCount() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        Path root = TestPathSupport.createDirectory("file-export-reimport");
        String indexName = IndexNaming.indexNameForShortName("traffic");
        RuntimeConfig.updateState(fileOnlyNdjsonState(root));
        OpenSearchCleanupIT.deleteAttackFrameworkIndexesNow();
        OpenSearchReachable.createSelectedIndexes(List.of("traffic"));

        PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, sampleDocument());
        FileExportService.emit(prepared);

        Path ndjsonPath = root.resolve(indexName + ".ndjson");
        assertThat(ndjsonPath).exists();
        String payload = Files.readString(ndjsonPath);
        assertThat(payload).contains("\"_id\":\"" + prepared.exportId() + "\"");

        bulkImport(indexName, payload);
        long countAfterFirst = countDocuments(indexName);

        bulkImport(indexName, payload);
        long countAfterSecond = countDocuments(indexName);

        assertThat(countAfterFirst).isEqualTo(1L);
        assertThat(countAfterSecond).isEqualTo(countAfterFirst);
    }

    private static ConfigState.State fileOnlyNdjsonState(Path root) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(true, root.toString(), false, true,
                        true, ConfigState.DEFAULT_FILE_TOTAL_CAP_BYTES,
                        false, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false, "", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("PROXY"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );
    }

    private static Map<String, Object> sampleDocument() {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        meta.put("indexed_at", "2026-03-28T00:00:00Z");

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("method", "GET");

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", "https://acme.com/reimport");
        document.put("method", "GET");
        document.put("tool_type", "PROXY");
        document.put("request", request);
        document.put("document_meta", meta);
        return document;
    }

    @SuppressWarnings("deprecation")
    private static void bulkImport(String indexName, String payload) throws IOException {
        String baseUrl = OpenSearchReachable.getBaseUrl();
        String bulkUrl = (baseUrl.endsWith("/") ? baseUrl + indexName + "/_bulk" : baseUrl + "/" + indexName + "/_bulk")
                + "?refresh=wait_for";
        HttpPost post = new HttpPost(bulkUrl);
        post.setEntity(new StringEntity(payload, ContentType.create("application/x-ndjson")));
        addBasicAuthIfConfigured(post);

        CloseableHttpClient client = OpenSearchConnector.getClassicHttpClient(
                baseUrl, OpenSearchReachable.getUsername(), OpenSearchReachable.getPassword());
        try (CloseableHttpResponse response = client.execute(post)) {
            String body;
            try {
                body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            } catch (ParseException e) {
                throw new IOException("Failed to parse bulk response body", e);
            }
            assertThat(response.getCode()).isBetween(200, 299);
            JsonNode root = JSON.readTree(body);
            assertThat(root.path("errors").asBoolean(true)).isFalse();
        }
    }

    private static long countDocuments(String indexName) throws IOException {
        return OpenSearchReachable.getClient().count(b -> b.index(indexName)).count();
    }

    private static void addBasicAuthIfConfigured(HttpPost post) {
        String username = OpenSearchReachable.getUsername();
        String password = OpenSearchReachable.getPassword();
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            return;
        }
        String token = Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        post.setHeader("Authorization", "Basic " + token);
    }
}
