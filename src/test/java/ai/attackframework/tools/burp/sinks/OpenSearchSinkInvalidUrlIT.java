package ai.attackframework.tools.burp.sinks;

import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Negative-path validation: malformed endpoint should yield FAILED status.
 */
@Tag("integration")
class OpenSearchSinkInvalidUrlIT {

    @Test
    void createIndexFromResource_returnsFailed_whenUrlMalformed() {
        IndexResult res = OpenSearchSink.createIndexFromResource("not_a_url", "traffic");
        assertThat(res.shortName()).isEqualTo("traffic");
        assertThat(res.fullName()).endsWith("-traffic");
        assertThat(res.status()).isEqualTo(IndexResult.Status.FAILED);
    }
}
