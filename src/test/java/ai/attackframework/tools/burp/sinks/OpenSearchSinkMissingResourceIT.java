package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;

/**
 * Negative-path validation: missing mapping resource should yield FAILED status.
 */
@Tag("integration")
class OpenSearchSinkMissingResourceIT {

    @Test
    void createIndexFromResource_returnsFailed_whenMappingResourceMissing() {
        // "nonexistent" does not correspond to any mapping file under resources/opensearch/mappings
        IndexResult res = OpenSearchSink.createIndexFromResource("http://opensearch.url:9200", "nonexistent");

        assertThat(res.shortName()).isEqualTo("nonexistent");
        assertThat(res.fullName()).endsWith("-nonexistent");
        assertThat(res.status()).isEqualTo(IndexResult.Status.FAILED);
    }
}
