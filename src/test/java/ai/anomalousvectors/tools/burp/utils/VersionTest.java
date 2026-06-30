package ai.anomalousvectors.tools.burp.utils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VersionTest {

    private String previous;

    @AfterEach
    public void restoreProperty() {
        if (previous == null) {
            System.clearProperty("burp.exporter.version");
        } else {
            System.setProperty("burp.exporter.version", previous);
        }
    }

    @Test
    void get_uses_system_property_override_in_tests() {
        previous = System.getProperty("burp.exporter.version");
        System.setProperty("burp.exporter.version", "9.9.9-test");
        String v = Version.get();
        assertThat(v).isEqualTo("9.9.9-test");
    }

    @Test
    void get_returns_gradle_injected_version_when_override_not_changed() {
        // Gradle's test task sets -Dburp.exporter.version=<project.version>
        String injected = System.getProperty("burp.exporter.version");
        String v = Version.get();
        assertThat(injected).isNotBlank();
        assertThat(v).isEqualTo(injected);
    }
}
