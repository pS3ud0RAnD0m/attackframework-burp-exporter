package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AboutPanelMissingVersionHeadlessTest {

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
    void constructor_throws_when_version_not_available() {
        System.clearProperty("attackframework.version");
        assertThatThrownBy(AboutPanel::new)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Implementation-Version not found");
    }
}
