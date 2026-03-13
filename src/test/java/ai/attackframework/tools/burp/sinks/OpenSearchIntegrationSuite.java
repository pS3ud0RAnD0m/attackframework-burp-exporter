package ai.attackframework.tools.burp.sinks;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

/**
 * JUnit 5 suite that runs all OpenSearch sink integration tests, then
 * {@link OpenSearchCleanupIT} (last) deletes the created indexes in @AfterAll.
 *
 * <p>Includes a nested placeholder so the suite always discovers at least one test when
 * a test filter is applied (e.g. {@code --tests "*ConfigPanel*"}), avoiding
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
    OpenSearchIntegrationSuite.class  // include self so nested placeholder is discovered
})
class OpenSearchIntegrationSuite {

    @Nested
    class OpenSearchIntegrationSuiteConfigPanelPlaceholder {
        @Test
        void suitePlaceholder() {
            // Ensures suite discovers at least one test when filters (e.g. *ConfigPanel*) exclude all selected IT classes.
        }
    }
}
