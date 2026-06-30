package ai.anomalousvectors.tools.burp.ui;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AboutPanelMissingVersionHeadlessTest {

    private String previous;

    @BeforeEach
    public void stash() {
        previous = System.getProperty("burp.exporter.version");
    }

    @AfterEach
    public void restore() {
        if (previous == null) {
            System.clearProperty("burp.exporter.version");
        } else {
            System.setProperty("burp.exporter.version", previous);
        }
    }

    @Test
    void constructor_throws_when_version_not_available() {
        System.clearProperty("burp.exporter.version");
        assertThatThrownBy(AboutPanel::new)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Implementation-Version not found");
    }
}
