package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ExporterIndexStatsSnapshotKeysTest {

    @Test
    void statsSnapshotIndexKey_mapsExporterToExporterIndex() {
        assertThat(ExporterIndexStatsReporter.statsSnapshotIndexKey("exporter"))
                .isEqualTo(ExporterIndexStatsReporter.EXPORTER_INDEX_STATS_KEY);
        assertThat(ExporterIndexStatsReporter.statsSnapshotIndexKey("traffic")).isEqualTo("traffic");
    }
}
