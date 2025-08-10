package ai.attackframework.vectors.sources.burp.sinks;

import ai.attackframework.vectors.sources.burp.sinks.OpenSearchSink.IndexResult;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Negative-path validation: unreachable OpenSearch endpoint should yield FAILED status.
 */
@Tag("integration")
class OpenSearchSinkErrorIT {

    // Non-routable / guaranteed-fail endpoint for negative testing
    private static final String BAD_URL = "http://127.0.0.1:9";

    @Test
    void createIndexFromResource_returnsFailed_whenEndpointUnreachable() {
        IndexResult res = OpenSearchSink.createIndexFromResource(BAD_URL, "traffic");
        assertThat(res.shortName()).isEqualTo("traffic");
        assertThat(res.fullName()).endsWith("-traffic"); // exact prefix validated elsewhere
        assertThat(res.status()).isEqualTo(IndexResult.Status.FAILED);
    }
}
