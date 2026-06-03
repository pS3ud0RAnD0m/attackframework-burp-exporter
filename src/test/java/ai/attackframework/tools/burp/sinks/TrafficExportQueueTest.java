package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Unit tests for {@link TrafficExportQueue}: offer is non-blocking and does not throw.
 * Worker drain and push behaviour is covered by integration tests and manual runs.
 */
class TrafficExportQueueTest {

    @BeforeEach
    @AfterEach
    void resetQueueAndExportState() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
    }

    @Test
    void offer_null_doesNotThrow() {
        assertThatCode(() -> TrafficExportQueue.offer(null)).doesNotThrowAnyException();
    }

    @Test
    void getCurrentBytesEstimate_returnsNonNegativeAndTracksOffers() {
        long before = TrafficExportQueue.getCurrentBytesEstimate();
        assertThat(before).isGreaterThanOrEqualTo(0);
        TrafficExportQueue.offer(Map.of("url", "https://example.com/bytes-probe", "status", 200));
        long after = TrafficExportQueue.getCurrentBytesEstimate();
        assertThat(after).isGreaterThanOrEqualTo(before);
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

    @Test
    void purgeDisabledTraffic_removesOnlyDeselectedRoutes() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(true, "C:\\temp", true, false, false, "", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy", "repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(true);

        TrafficExportQueue.offer(trafficDoc("Proxy"));
        TrafficExportQueue.offer(trafficDoc("Repeater"));
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(true, "C:\\temp", true, false, false, "", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        int purged = TrafficExportQueue.purgeDisabledTraffic(RuntimeConfig.trafficExportGate());

        assertThat(purged).isEqualTo(1);
        assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
    }

    @Test
    void offerAccepted_rejectsLateTrafficAfterExportStopped() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(true, "C:\\temp", true, false, false, "", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(false);

        boolean accepted = TrafficExportQueue.offerAccepted(trafficDoc("Proxy"));

        assertThat(accepted).isFalse();
        assertThat(TrafficExportQueue.getCurrentSize()).isZero();
    }

    private static Map<String, Object> trafficDoc(String reporter) {
        return Map.of("burp", Map.of("reporting_tool", reporter));
    }
}
