package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies error surfacing: invalid JSON should propagate an IOException.
 */
class JsonParseErrorTest {

    @Test
    void parse_invalid_json_throwsIOException() {
        String invalid = "{";
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class);
    }
}
