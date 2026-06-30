package ai.anomalousvectors.tools.burp.utils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VersionStrictnessTest {

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
    void get_throws_when_override_is_blank() {
        System.setProperty("burp.exporter.version", "");
        assertThatThrownBy(Version::get)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Implementation-Version not found");
    }

    @Test
    void get_throws_when_override_is_cleared() {
        System.clearProperty("burp.exporter.version");
        assertThatThrownBy(Version::get)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Implementation-Version not found");
    }
}
