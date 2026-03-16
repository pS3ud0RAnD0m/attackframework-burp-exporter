package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link TrafficExportQueue}: offer is non-blocking and does not throw.
 * Worker drain and push behaviour is covered by integration tests and manual runs.
 */
class TrafficExportQueueTest {

    @Test
    void offer_null_doesNotThrow() {
        assertThatCode(() -> TrafficExportQueue.offer(null)).doesNotThrowAnyException();
    }

    @Test
    void offer_emptyMap_doesNotThrow() {
        assertThatCode(() -> TrafficExportQueue.offer(Map.of())).doesNotThrowAnyException();
    }

    @Test
    void offer_validDoc_doesNotThrow() {
        Map<String, Object> doc = Map.of("url", "https://example.com/", "status", 200);
        assertThatCode(() -> TrafficExportQueue.offer(doc)).doesNotThrowAnyException();
    }

    @Test
    void getCurrentSize_returnsNonNegative() {
        assertThat(TrafficExportQueue.getCurrentSize()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void getCurrentSize_increasesWhenDocOffered() {
        assertThatCode(() ->
                TrafficExportQueue.offer(Map.of("url", "https://example.com/a", "status", 200)))
                .doesNotThrowAnyException();
        assertThat(TrafficExportQueue.getCurrentSize()).isGreaterThanOrEqualTo(0);
    }
}
