package ai.anomalousvectors.tools.burp.testutils;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

/**
 * Enforces documented test conventions from {@code java-testing.mdc} on every {@code ./gradlew test} / {@code build}.
 */
class JavaTestingConventionsTest {

    @Test
    void testSources_followJavaTestingMdcConventions() throws Exception {
        var violations = JavaTestingConventionScanner.scan(Path.of("src/test/java"));
        String details = violations.stream().map(violation -> violation.toString()).collect(Collectors.joining("\n"));
        assertThat(violations)
                .withFailMessage("Test convention violations (see .cursor/rules/java-testing.mdc):\n%s", details)
                .isEmpty();
    }
}
