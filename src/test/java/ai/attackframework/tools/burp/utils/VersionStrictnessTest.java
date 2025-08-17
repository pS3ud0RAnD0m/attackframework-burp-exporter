package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VersionStrictnessTest {

    private String previous;

    @BeforeEach
    void stash() {
        previous = System.getProperty("attackframework.version");
    }

    @AfterEach
    void restore() {
        if (previous == null) {
            System.clearProperty("attackframework.version");
        } else {
            System.setProperty("attackframework.version", previous);
        }
    }

    @Test
    void get_throws_when_override_is_blank() {
        System.setProperty("attackframework.version", "");
        assertThatThrownBy(Version::get)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Implementation-Version not found");
    }

    @Test
    void get_throws_when_override_is_cleared() {
        System.clearProperty("attackframework.version");
        assertThatThrownBy(Version::get)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Implementation-Version not found");
    }
}
