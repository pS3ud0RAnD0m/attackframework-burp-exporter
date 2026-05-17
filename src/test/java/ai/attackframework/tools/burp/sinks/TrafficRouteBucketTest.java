package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.FileExportStats;

/**
 * Unit tests for the centralized {@link TrafficRouteBucket} mapping and stats helpers.
 *
 * <p>The class is the single authority for deciding whether a traffic document rolls up under
 * a {@link TrafficRouteBucket.Kind#SOURCE} or {@link TrafficRouteBucket.Kind#TOOL_TYPE} bucket,
 * and for recording per-bucket counts on both the OpenSearch and file sinks.</p>
 */
class TrafficRouteBucketTest {

    @AfterEach
    void resetStats() {
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
    }

    @Test
    void fromToolType_routesProxyHistoryToSnapshotSource() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.fromToolType("PROXY_HISTORY");
        assertThat(route.kind()).isEqualTo(TrafficRouteBucket.Kind.SOURCE);
        assertThat(route.key()).isEqualTo(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT);
    }

    @Test
    void fromToolType_routesProxyWebSocketToSource() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.fromToolType("PROXY_WEBSOCKET");
        assertThat(route.kind()).isEqualTo(TrafficRouteBucket.Kind.SOURCE);
        assertThat(route.key()).isEqualTo(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET);
    }

    @Test
    void fromToolType_passesThroughOtherToolTypesAsToolType() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.fromToolType("REPEATER_TABS");
        assertThat(route.kind()).isEqualTo(TrafficRouteBucket.Kind.TOOL_TYPE);
        assertThat(route.key()).isEqualTo("REPEATER_TABS");
    }

    @Test
    void fromToolType_normalizesBlankAndNullToUnknown() {
        assertThat(TrafficRouteBucket.fromToolType(null).key()).isEqualTo(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);
        assertThat(TrafficRouteBucket.fromToolType("").key()).isEqualTo(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);
        assertThat(TrafficRouteBucket.fromToolType("   ").key()).isEqualTo(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);
    }

    @Test
    void fromDocument_derivesRouteFromToolTypeField() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("tool_type", "PROXY_WEBSOCKET");
        assertThat(TrafficRouteBucket.fromDocument(doc).key())
                .isEqualTo(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET);

        Map<String, Object> docWithoutToolType = new HashMap<>();
        assertThat(TrafficRouteBucket.fromDocument(docWithoutToolType).key())
                .isEqualTo(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);

        assertThat(TrafficRouteBucket.fromDocument(null).key())
                .isEqualTo(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);
    }

    @Test
    void routeRecord_rejectsBlankKeyOrNullKind() {
        assertThatThrownBy(() -> new TrafficRouteBucket.Route(null, "x"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TrafficRouteBucket.Route(TrafficRouteBucket.Kind.TOOL_TYPE, ""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void recordOpenSearchSuccess_routesSourceAndToolTypeSeparately() {
        TrafficRouteBucket.recordOpenSearchSuccess(TrafficRouteBucket.proxyHistorySnapshot(), 3);
        TrafficRouteBucket.recordOpenSearchSuccess(TrafficRouteBucket.fromToolType("REPEATER_TABS"), 2);

        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(3);
        assertThat(ExportStats.getTrafficToolTypeSuccessCount("REPEATER_TABS")).isEqualTo(2);
    }

    @Test
    void recordOpenSearchFailure_routesSourceAndToolTypeSeparately() {
        TrafficRouteBucket.recordOpenSearchFailure(TrafficRouteBucket.proxyWebSocket(), 4);
        TrafficRouteBucket.recordOpenSearchFailure(TrafficRouteBucket.fromToolType("INTRUDER"), 1);

        assertThat(ExportStats.getTrafficSourceFailureCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isEqualTo(4);
        assertThat(ExportStats.getTrafficToolTypeFailureCount("INTRUDER")).isEqualTo(1);
    }

    @Test
    void recordFileSuccessAndFailure_updateFileExportStats() {
        TrafficRouteBucket.recordFileSuccess(TrafficRouteBucket.proxyHistorySnapshot(), 5);
        TrafficRouteBucket.recordFileFailure(TrafficRouteBucket.fromToolType("REPEATER"), 7);

        assertThat(FileExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(5);
        assertThat(FileExportStats.getTrafficToolTypeFailureCount("REPEATER")).isEqualTo(7);
    }

    @Test
    void resolveOpenSearchSourceSuccess_foldsSnapshotAndWebSocketUnderProxyHistoryRow() {
        TrafficRouteBucket.recordOpenSearchSuccess(
                TrafficRouteBucket.fromToolType("PROXY_HISTORY"), 2); // proxy_history_snapshot
        TrafficRouteBucket.recordOpenSearchSuccess(TrafficRouteBucket.proxyWebSocket(), 3);
        // A plain PROXY_HISTORY tool-type value should never land in the tool-type map because
        // the route bucket always resolves PROXY_HISTORY -> SOURCE, but confirm the display path
        // is stable when the tool-type map is empty.
        assertThat(TrafficRouteBucket.resolveOpenSearchSourceSuccess("PROXY_HISTORY")).isEqualTo(5);
        assertThat(TrafficRouteBucket.resolveOpenSearchSourceFailure("PROXY_HISTORY")).isZero();
    }

    @Test
    void resolveFileSourceSuccess_foldsSnapshotAndWebSocketUnderProxyHistoryRow() {
        TrafficRouteBucket.recordFileSuccess(TrafficRouteBucket.proxyHistorySnapshot(), 4);
        TrafficRouteBucket.recordFileSuccess(TrafficRouteBucket.proxyWebSocket(), 1);
        assertThat(TrafficRouteBucket.resolveFileSourceSuccess("PROXY_HISTORY")).isEqualTo(5);
    }

    @Test
    void recordBulkOutcome_fullSuccess_updatesTrafficAndRouteSuccessCounters() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocket();
        TrafficRouteBucket.recordBulkOutcome(route, 4, 4, true, "Proxy WebSocket bulk push");

        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(4);
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isEqualTo(4);
        assertThat(ExportStats.getTrafficSourceFailureCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isZero();
    }

    @Test
    void recordBulkOutcome_partialFailure_splitsSuccessAndFailure() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyHistorySnapshot();
        TrafficRouteBucket.recordBulkOutcome(route, 5, 3, true, "Proxy history chunk");

        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(3);
        assertThat(ExportStats.getFailureCount("traffic")).isEqualTo(2);
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(3);
        assertThat(ExportStats.getTrafficSourceFailureCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(2);
    }

    @Test
    void recordBulkOutcome_openSearchInactive_isNoop() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocket();
        TrafficRouteBucket.recordBulkOutcome(route, 4, 2, false, "label");

        assertThat(ExportStats.getSuccessCount("traffic")).isZero();
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isZero();
        assertThat(ExportStats.getTrafficSourceFailureCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isZero();
    }

    @Test
    void recordBulkOutcome_nullRoute_isNoop() {
        TrafficRouteBucket.recordBulkOutcome(null, 3, 3, true, "label");
        assertThat(ExportStats.getSuccessCount("traffic")).isZero();
    }

    @Test
    void recordBulkOutcome_clampsSentAboveAttempted() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyHistorySnapshot();
        TrafficRouteBucket.recordBulkOutcome(route, 5, 7, true, "Proxy history chunk");

        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(5);
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_HISTORY_SNAPSHOT))
                .isEqualTo(5);
    }

    @Test
    void recordBulkOutcome_clampsNegativeAttemptedToZero() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocket();
        TrafficRouteBucket.recordBulkOutcome(route, -3, 5, true, "label");

        assertThat(ExportStats.getSuccessCount("traffic")).isZero();
        assertThat(ExportStats.getFailureCount("traffic")).isZero();
        assertThat(ExportStats.getTrafficSourceSuccessCount(TrafficRouteBucket.SOURCE_PROXY_WEBSOCKET))
                .isZero();
    }

    @Test
    void trafficIndexName_delegatesToRuntimeConfig() {
        String name = TrafficRouteBucket.trafficIndexName();
        assertThat(name).isNotNull();
        assertThat(TrafficRouteBucket.INDEX_KEY).isEqualTo("traffic");
    }

    @Test
    void zeroOrNegativeCount_recordsNothing() {
        TrafficRouteBucket.recordOpenSearchSuccess(TrafficRouteBucket.fromToolType("REPEATER"), 0);
        TrafficRouteBucket.recordOpenSearchFailure(TrafficRouteBucket.fromToolType("REPEATER"), -2);
        TrafficRouteBucket.recordFileSuccess(TrafficRouteBucket.fromToolType("REPEATER"), 0);
        TrafficRouteBucket.recordFileFailure(TrafficRouteBucket.fromToolType("REPEATER"), -9);

        assertThat(ExportStats.getTrafficToolTypeSuccessCount("REPEATER")).isZero();
        assertThat(ExportStats.getTrafficToolTypeFailureCount("REPEATER")).isZero();
        assertThat(FileExportStats.getTrafficToolTypeSuccessCount("REPEATER")).isZero();
        assertThat(FileExportStats.getTrafficToolTypeFailureCount("REPEATER")).isZero();
    }
}
