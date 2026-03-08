package ai.attackframework.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ChunkedBulkSender}: URL building, response parsing, and push with
 * empty queue. Full drain and HTTP behaviour are covered by integration tests.
 */
class ChunkedBulkSenderTest {

    @Test
    void buildBulkUrl_normalizesTrailingSlash() {
        assertThat(ChunkedBulkSender.buildBulkUrl("http://localhost:9200/", "my-index"))
                .isEqualTo("http://localhost:9200/my-index/_bulk");
    }

    @Test
    void buildBulkUrl_noTrailingSlash() {
        assertThat(ChunkedBulkSender.buildBulkUrl("http://localhost:9200", "attackframework-tool-burp-traffic"))
                .isEqualTo("http://localhost:9200/attackframework-tool-burp-traffic/_bulk");
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
                "http://localhost:9999", "test-index", queue, 10, 5 * 1024 * 1024, 50);
        assertThat(r.attemptedCount).isZero();
        assertThat(r.successCount).isZero();
    }
}
