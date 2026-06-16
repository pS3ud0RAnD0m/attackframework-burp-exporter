package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.getStaticLinkedBlockingQueue;
import static ai.attackframework.tools.burp.testutils.SnapshotExportEngineTestSupport.preparedTrafficDoc;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.LinkedBlockingQueue;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;

/** Synthetic load tests for {@link TrafficExportQueue} depth and byte accounting. */
class TrafficExportQueueScaleTest {

    @Test
    void enqueue_manyPreparedEntries_tracksDepthAndBytes() throws Exception {
        ExportStats.resetForTests();
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            LinkedBlockingQueue<TrafficQueueEntry> queue = trafficQueue();
            int offers = 5_000;
            long bytesPerDoc = 4_096L;
            String indexName = IndexNaming.indexNameForShortName("traffic");
            for (int i = 0; i < offers; i++) {
                queue.offer(TrafficQueueEntry.fromPrepared(preparedTrafficDoc(indexName, i, bytesPerDoc)));
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

    private static LinkedBlockingQueue<TrafficQueueEntry> trafficQueue() {
        return getStaticLinkedBlockingQueue(TrafficExportQueue.class, "queue");
    }
}
