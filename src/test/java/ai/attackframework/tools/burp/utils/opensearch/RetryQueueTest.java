package ai.attackframework.tools.burp.utils.opensearch;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RetryQueue}: offer, pollBatch, bounded capacity, batch size.
 */
class RetryQueueTest {

    @Test
    void offer_pollBatch_roundTrip() {
        RetryQueue queue = new RetryQueue(100);
        String indexName = "test-index";
        Map<String, Object> doc = Map.of("id", "1");
        assertThat(queue.offer(indexName, doc)).isTrue();
        assertThat(queue.size(indexName)).isEqualTo(1);
        List<Map<String, Object>> batch = queue.pollBatch(indexName, 10);
        assertThat(batch).hasSize(1).containsExactly(doc);
        assertThat(queue.isEmpty(indexName)).isTrue();
    }

    @Test
    void offerAll_whenFull_dropsExcess() {
        RetryQueue queue = new RetryQueue(2);
        String indexName = "test-index";
        int added = queue.offerAll(indexName, List.of(
                Map.of("a", 1),
                Map.of("b", 2),
                Map.of("c", 3)));
        assertThat(added).isEqualTo(2);
        assertThat(queue.size(indexName)).isEqualTo(2);
    }

    @Test
    void pollBatch_respectsMaxSize() {
        RetryQueue queue = new RetryQueue(100);
        String indexName = "test-index";
        queue.offerAll(indexName, List.of(Map.of("a", 1), Map.of("b", 2), Map.of("c", 3)));
        List<Map<String, Object>> batch = queue.pollBatch(indexName, 2);
        assertThat(batch).hasSize(2);
        assertThat(queue.size(indexName)).isEqualTo(1);
    }

    @Test
    void pollBatch_emptyIndex_returnsEmptyList() {
        RetryQueue queue = new RetryQueue(100);
        List<Map<String, Object>> batch = queue.pollBatch("no-such-index", 10);
        assertThat(batch).isEmpty();
    }
}
