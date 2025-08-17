package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VersionTest {

    private String previous;

    @AfterEach
    void restoreProperty() {
        if (previous == null) {
            System.clearProperty("attackframework.version");
        } else {
            System.setProperty("attackframework.version", previous);
        }
    }

    @Test
    void get_uses_system_property_override_in_tests() {
        previous = System.getProperty("attackframework.version");
        System.setProperty("attackframework.version", "9.9.9-test");
        String v = Version.get();
        assertThat(v).isEqualTo("9.9.9-test");
    }

    @Test
    void get_returns_gradle_injected_version_when_override_not_changed() {
        // Gradle's test task sets -Dattackframework.version=<project.version>
        String injected = System.getProperty("attackframework.version");
        String v = Version.get();
        assertThat(injected).isNotBlank();
        assertThat(v).isEqualTo(injected);
    }
}
