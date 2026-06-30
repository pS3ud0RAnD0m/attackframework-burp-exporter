package ai.anomalousvectors.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ExportStartupStatusTest {

    @Test
    void initialStartingMessage_filesOnly() {
        ExportStartupStatus.Snapshot snapshot = new ExportStartupStatus.Snapshot(true, false);

        assertThat(ExportStartupStatus.initialStartingMessage(snapshot))
                .isEqualTo("Starting: preparing Files export …");
    }

    @Test
    void initialStartingMessage_bothDestinations() {
        ExportStartupStatus.Snapshot snapshot = new ExportStartupStatus.Snapshot(true, true);

        assertThat(ExportStartupStatus.initialStartingMessage(snapshot))
                .isEqualTo("Starting: preparing Files and OpenSearch export …");
    }

    @Test
    void initializingFilesMessage_usesStartingPrefix() {
        assertThat(ExportStartupStatus.initializingFilesMessage())
                .isEqualTo("Starting: initializing file export …");
    }

    @Test
    void creatingOpenSearchIndexesMessage_usesStartingPrefix() {
        assertThat(ExportStartupStatus.creatingOpenSearchIndexesMessage())
                .isEqualTo("Starting: creating OpenSearch indexes …");
    }
}
