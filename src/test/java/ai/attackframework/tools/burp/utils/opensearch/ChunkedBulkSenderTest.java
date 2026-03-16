package ai.attackframework.tools.burp.utils.opensearch;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Unit tests for {@link ChunkedBulkSender}: URL building, response parsing, and push with
 * empty queue. Full drain and HTTP behaviour are covered by integration tests.
 */
class ChunkedBulkSenderTest {

    @Test
    void buildBulkUrl_normalizesTrailingSlash() {
        assertThat(ChunkedBulkSender.buildBulkUrl("https://opensearch.url:9200/", "my-index"))
                .isEqualTo("https://opensearch.url:9200/my-index/_bulk");
    }

    @Test
    void buildBulkUrl_noTrailingSlash() {
        assertThat(ChunkedBulkSender.buildBulkUrl("https://opensearch.url:9200", "attackframework-tool-burp-traffic"))
                .isEqualTo("https://opensearch.url:9200/attackframework-tool-burp-traffic/_bulk");
    }

    @Test
    void parseBulkResponse_emptyBody_returnsZeroSuccess() {
        ChunkedBulkSender.Result r = ChunkedBulkSender.parseBulkResponse("", 5);
        assertThat(r.successCount).isZero();
        assertThat(r.attemptedCount).isEqualTo(5);
    }

    @Test
    void parseBulkResponse_nullBody_returnsZeroSuccess() {
        ChunkedBulkSender.Result r = ChunkedBulkSender.parseBulkResponse(null, 3);
        assertThat(r.successCount).isZero();
        assertThat(r.attemptedCount).isEqualTo(3);
    }

    @Test
    void parseBulkResponse_validItems_countsSuccess() {
        String body = "{\"took\":1,\"errors\":false,\"items\":["
                + "{\"index\":{\"_index\":\"t\",\"status\":201}},"
                + "{\"index\":{\"_index\":\"t\",\"status\":200}}]}";
        ChunkedBulkSender.Result r = ChunkedBulkSender.parseBulkResponse(body, 2);
        assertThat(r.successCount).isEqualTo(2);
        assertThat(r.attemptedCount).isEqualTo(2);
        assertThat(r.isFullSuccess()).isTrue();
    }

    @Test
    void parseBulkResponse_oneFailure_countsCorrectly() {
        String body = "{\"took\":1,\"errors\":true,\"items\":["
                + "{\"index\":{\"_index\":\"t\",\"status\":201}},"
                + "{\"index\":{\"_index\":\"t\",\"status\":400}}]}";
        ChunkedBulkSender.Result r = ChunkedBulkSender.parseBulkResponse(body, 2);
        assertThat(r.successCount).isEqualTo(1);
        assertThat(r.attemptedCount).isEqualTo(2);
        assertThat(r.isFullSuccess()).isFalse();
    }

    @Test
    void push_emptyQueue_returnsZeroAttempted_afterShortWait() {
        LinkedBlockingQueue<Map<String, Object>> queue = new LinkedBlockingQueue<>();
        ChunkedBulkSender.Result r = ChunkedBulkSender.push(
                "http://opensearch.url:9999", "test-index", queue, 10, 5 * 1024 * 1024, 50);
        assertThat(r.attemptedCount).isZero();
        assertThat(r.successCount).isZero();
    }

    @Test
    void addPreemptiveBasicAuthHeader_setsHeader_whenCredentialsConfigured() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(stateWithOpenSearchCreds("alice", "s3cr3t"));
            HttpPost post = new HttpPost("https://opensearch.url:9200/_bulk");

            ChunkedBulkSender.addPreemptiveBasicAuthHeader(post);

            String expected = "Basic "
                    + Base64.getEncoder().encodeToString("alice:s3cr3t".getBytes(StandardCharsets.UTF_8));
            assertThat(post.getFirstHeader("Authorization")).isNotNull();
            assertThat(post.getFirstHeader("Authorization").getValue()).isEqualTo(expected);
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void addPreemptiveBasicAuthHeader_doesNothing_whenCredentialsMissing() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(stateWithOpenSearchCreds("", ""));
            HttpPost post = new HttpPost("https://opensearch.url:9200/_bulk");

            ChunkedBulkSender.addPreemptiveBasicAuthHeader(post);

            assertThat(post.getFirstHeader("Authorization")).isNull();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    private static ConfigState.State stateWithOpenSearchCreds(String user, String pass) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", user, pass, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );
    }
}
