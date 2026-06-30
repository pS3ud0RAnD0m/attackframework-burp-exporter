package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;

class TrafficLiveAttributionSummaryTest {

    @Test
    void formatSummaryLine_includesOnlyNonZeroSections() {
        String line = TrafficLiveAttributionSummary.formatSummaryLine(
                Map.of("Scanner", 413L),
                Map.of("Scanner", 413L),
                0L,
                0L,
                0L);

        assertThat(line).isEqualTo("[LiveTraffic] Traffic: attribution summary: "
                + "openSearch={Scanner=413}; file={Scanner=413}.");
    }

    @Test
    void formatSummaryLine_returnsNullForEmptySummary() {
        assertThat(TrafficLiveAttributionSummary.formatSummaryLine(
                Map.of(), Map.of(), 0L, 0L, 0L)).isNull();
    }

    @Test
    void logAndClear_withoutStart_isNoOp() {
        TrafficLiveAttributionSummary.clearRunState();
        TrafficLiveAttributionSummary.logAndClearForCurrentRun();
    }

    @Test
    void formatSummaryLine_excludesStartupRepeaterTabsFromLiveDeltas() {
        String line = TrafficLiveAttributionSummary.formatSummaryLine(
                TrafficLiveAttributionSummary.liveDeltasForTests(
                        Map.of(), Map.of("REPEATER_TABS", 15L, "SCANNER", 260L)),
                TrafficLiveAttributionSummary.liveDeltasForTests(
                        Map.of(), Map.of("REPEATER_TABS", 15L, "SCANNER", 260L)),
                0L,
                0L,
                0L);

        assertThat(line).isEqualTo("[LiveTraffic] Traffic: attribution summary: "
                + "openSearch={Scanner=260}; file={Scanner=260}.");
    }
}
