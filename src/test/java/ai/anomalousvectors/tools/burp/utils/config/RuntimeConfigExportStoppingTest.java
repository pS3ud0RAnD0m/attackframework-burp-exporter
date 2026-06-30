package ai.anomalousvectors.tools.burp.utils.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RuntimeConfigExportStoppingTest {

    @AfterEach
    public void reset() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStopping(false);
    }

    @Test
    void setExportStopping_tracksStoppingState() {
        assertThat(RuntimeConfig.isExportStopping()).isFalse();

        RuntimeConfig.setExportStopping(true);

        assertThat(RuntimeConfig.isExportStopping()).isTrue();
    }

    @Test
    void setExportRunning_false_clearsExportStopping() {
        RuntimeConfig.setExportStopping(true);

        RuntimeConfig.setExportRunning(false);

        assertThat(RuntimeConfig.isExportStopping()).isFalse();
        assertThat(RuntimeConfig.isExportRunning()).isFalse();
    }
}
