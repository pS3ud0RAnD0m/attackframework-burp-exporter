package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.SnapshotExportEngineTestSupport.preparedTrafficDoc;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;

/** Synthetic load tests for {@link TrafficExportQueue} depth and byte accounting. */
class TrafficExportQueueScaleTest {

    @Test
    void enqueue_manyPreparedEntries_tracksDepthAndBytes() throws Exception {
        ExportStats.resetForTests();
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            int offers = 5_000;
            long bytesPerDoc = 4_096L;
            String indexName = IndexNaming.indexNameForShortName("traffic");
            for (int i = 0; i < offers; i++) {
                assertThat(TrafficExportQueue.offerPreparedForTests(preparedTrafficDoc(indexName, i, bytesPerDoc)))
                        .isTrue();
            }

            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(offers);
            assertThat(TrafficExportQueue.getCurrentBytesEstimate()).isEqualTo(offers * bytesPerDoc);

            ExportStats.observeExportPressureSamples(
                    TrafficExportQueue.getCurrentSize(),
                    TrafficExportQueue.getCurrentBytesEstimate(),
                    0,
                    0L,
                    0,
                    0L);
            assertThat(ExportStats.getPeakTrafficQueueDocs()).isEqualTo(offers);
            assertThat(ExportStats.getPeakTrafficQueueBytes()).isEqualTo(offers * bytesPerDoc);
        });
    }
}
