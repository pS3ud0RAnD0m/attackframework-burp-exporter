package ai.anomalousvectors.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ExportShutdownStatusTest {

    @Test
    void initialStoppingMessage_noBacklog_mentionsBatchOnly() {
        ExportShutdownStatus.Snapshot snapshot = new ExportShutdownStatus.Snapshot(0, 0, 0, 500);

        assertThat(ExportShutdownStatus.initialStoppingMessage(snapshot))
                .isEqualTo("Stopping: waiting for in-flight traffic batch …");
    }

    @Test
    void initialStoppingMessage_withBacklog_includesClearingCount() {
        ExportShutdownStatus.Snapshot snapshot = new ExportShutdownStatus.Snapshot(10, 5, 3, 500);

        assertThat(ExportShutdownStatus.initialStoppingMessage(snapshot))
                .isEqualTo("Stopping: waiting for in-flight traffic batch, then clearing 18 queued docs …");
    }

    @Test
    void clearingQueuedTrafficMessage_usesSnapshotBacklog() {
        ExportShutdownStatus.Snapshot snapshot = new ExportShutdownStatus.Snapshot(1, 0, 0, 100);

        assertThat(ExportShutdownStatus.clearingQueuedTrafficMessage(snapshot))
                .isEqualTo("Stopping: clearing 1 queued docs …");
    }

    @Test
    void collectingOpenSearchCountsMessage_namesFinalCountCollection() {
        assertThat(ExportShutdownStatus.collectingOpenSearchCountsMessage())
                .isEqualTo("Stopping: collecting final OpenSearch counts …");
    }

    @Test
    void stoppedMessage_isShortFinalLine() {
        assertThat(ExportShutdownStatus.stoppedMessage()).isEqualTo("Stopped");
    }
}
