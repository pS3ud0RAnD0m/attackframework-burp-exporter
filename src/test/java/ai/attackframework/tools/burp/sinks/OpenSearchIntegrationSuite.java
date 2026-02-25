package ai.attackframework.tools.burp.sinks;

import org.junit.jupiter.api.Tag;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

/**
 * JUnit 5 suite that runs all OpenSearch sink integration tests, then
 * {@link OpenSearchCleanupIT} (last) deletes the created indexes in @AfterAll.
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
    OpenSearchCleanupIT.class
})
class OpenSearchIntegrationSuite {
}
