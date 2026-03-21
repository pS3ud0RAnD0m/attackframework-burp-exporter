package ai.attackframework.tools.burp.sinks;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

/**
 * JUnit 5 suite that runs the OpenSearch sink integration tests and broad cleanup.
 *
 * <p>Includes a suite-discovery bridge so the suite always discovers at least one test
 * when a test filter is applied (e.g. {@code --tests "*ConfigPanel*"}), avoiding
 * {@code NoTestsDiscoveredException}.
 */
@Suite
@Tag("integration")
@SelectClasses({
    OpenSearchSinkIT.class,
    OpenSearchSinkFreshCreateIT.class,
    OpenSearchSinkConcurrencyIT.class,
    OpenSearchSinkMappingsIT.class,
    OpenSearchSinkSubsetIT.class,
    OpenSearchSinkToolOnlyIT.class,
    OpenSearchCleanupIT.class,
    OpenSearchIntegrationSuite.class  // include self so the suite-discovery bridge is discovered
})
public class OpenSearchIntegrationSuite {

    @Test
    void suiteDiscoveryBridge_forFilteredRuns() {
        // Keeps suite discovery stable when filters exclude every selected IT class.
    }
}
