package ai.attackframework.vectors.sources.burp.utils;

import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class LoggerTest {

    @Test
    void registerListener_receivesInfoAndErrorLogs() {
        // Collect log events into a list for verification
        List<String> seen = new ArrayList<>();
        Logger.LogListener listener = (level, msg) -> seen.add(level + ":" + msg);

        Logger.registerListener(listener);

        Logger.logInfo("hello");
        Logger.logError("world");

        assertThat(seen).hasSize(2);
        assertThat(seen.get(0)).startsWith("INFO:").contains("hello");
        assertThat(seen.get(1)).startsWith("ERROR:").contains("world");
    }
}
