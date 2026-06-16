package ai.attackframework.tools.burp.utils.opensearch;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.export.ExportDocumentIdentity;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RetryQueue}: offer, pollBatch, bounded capacity, batch size.
 */
class RetryQueueTest {

    @Test
    void bytesEstimate_returnsZeroWhenEmptyOrAbsent() {
        RetryQueue queue = new RetryQueue(10);
        assertThat(queue.bytesEstimate("never-seen")).isZero();
        queue.offer("seen", prepared("seen", Map.of("k", "v")));
        queue.pollBatch("seen", 10);
        assertThat(queue.bytesEstimate("seen")).isZero();
    }

    @Test
    void bytesEstimate_tracksDocumentSize() {
        RetryQueue queue = new RetryQueue(10);
        String indexName = "size-index";
        queue.offer(indexName, prepared(indexName, Map.of("short", "x")));
        long oneDocBytes = queue.bytesEstimate(indexName);
        assertThat(oneDocBytes).isPositive();
        assertThat(oneDocBytes).isEqualTo(queue.computeBytesEstimateByWalk(indexName));
        queue.offer(indexName, prepared(indexName, Map.of("another", "y")));
        long twoDocsBytes = queue.bytesEstimate(indexName);
        assertThat(twoDocsBytes).isGreaterThan(oneDocBytes);
        assertThat(twoDocsBytes).isEqualTo(queue.computeBytesEstimateByWalk(indexName));
    }

    @Test
    void offer_pollBatch_roundTrip() {
        RetryQueue queue = new RetryQueue(100);
        String indexName = "test-index";
        Map<String, Object> doc = Map.of("id", "1");
        PreparedExportDocument prepared = prepared(indexName, doc);
        assertThat(queue.offer(indexName, prepared)).isTrue();
        assertThat(queue.size(indexName)).isEqualTo(1);
        List<PreparedExportDocument> batch = queue.pollBatch(indexName, 10);
        assertThat(batch).containsExactly(prepared);
        assertThat(queue.isEmpty(indexName)).isTrue();
    }

    @Test
    void offerAll_whenFull_dropsExcess() {
        RetryQueue queue = new RetryQueue(2);
        String indexName = "test-index";
        int added = queue.offerAll(indexName, List.of(
                prepared(indexName, Map.of("a", 1)),
                prepared(indexName, Map.of("b", 2)),
                prepared(indexName, Map.of("c", 3))));
        assertThat(added).isEqualTo(2);
        assertThat(queue.size(indexName)).isEqualTo(2);
    }

    @Test
    void pollBatch_respectsMaxSize() {
        RetryQueue queue = new RetryQueue(100);
        String indexName = "test-index";
        queue.offerAll(indexName, List.of(
                prepared(indexName, Map.of("a", 1)),
                prepared(indexName, Map.of("b", 2)),
                prepared(indexName, Map.of("c", 3))));
        List<PreparedExportDocument> batch = queue.pollBatch(indexName, 2);
        assertThat(batch).hasSize(2);
        assertThat(queue.size(indexName)).isEqualTo(1);
    }

    @Test
    void pollBatch_emptyIndex_returnsEmptyList() {
        RetryQueue queue = new RetryQueue(100);
        List<PreparedExportDocument> batch = queue.pollBatch("no-such-index", 10);
        assertThat(batch).isEmpty();
    }

    @Test
    void oldestEnqueuedAtMs_returnsMinusOneWhenEmpty_andHeadTimestampWhenNonEmpty() throws InterruptedException {
        RetryQueue queue = new RetryQueue(100);
        String indexName = "test-index";
        assertThat(queue.oldestEnqueuedAtMs(indexName)).isEqualTo(-1L);

        long before = System.currentTimeMillis();
        queue.offer(indexName, prepared(indexName, Map.of("a", 1)));
        Thread.sleep(2);
        queue.offer(indexName, prepared(indexName, Map.of("b", 2)));
        long after = System.currentTimeMillis();

        long head = queue.oldestEnqueuedAtMs(indexName);
        assertThat(head).isBetween(before, after);

        queue.pollBatch(indexName, 1);
        long newHead = queue.oldestEnqueuedAtMs(indexName);
        assertThat(newHead).isGreaterThanOrEqualTo(head);

        queue.pollBatch(indexName, 10);
        assertThat(queue.oldestEnqueuedAtMs(indexName)).isEqualTo(-1L);
    }

    private static PreparedExportDocument prepared(String indexName, Map<String, Object> document) {
        return ExportDocumentIdentity.prepare(indexName, "traffic", document);
    }
}
