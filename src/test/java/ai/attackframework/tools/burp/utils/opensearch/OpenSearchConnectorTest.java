package ai.attackframework.tools.burp.utils.opensearch;

import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link OpenSearchConnector}.
 * The connector configures the HTTP client with {@code HttpVersionPolicy.NEGOTIATE} so that
 * HTTP/2 is preferred with fallback to HTTP/1.1; see {@link OpenSearchConnector#buildClient}.
 */
class OpenSearchConnectorTest {

    private static final String DUMMY_URL = "https://localhost:9243";

    @Test
    void getClient_returnsNonNull() {
        OpenSearchClient client = OpenSearchConnector.getClient(DUMMY_URL);
        assertThat(client).isNotNull();
    }

    @Test
    void getClient_withSameKey_returnsSameCachedInstance() {
        OpenSearchClient a = OpenSearchConnector.getClient(DUMMY_URL);
        OpenSearchClient b = OpenSearchConnector.getClient(DUMMY_URL);
        assertThat(a).isSameAs(b);
    }

    @Test
    void getClient_withCredentials_returnsNonNull() {
        OpenSearchClient client = OpenSearchConnector.getClient(DUMMY_URL, "user", "pass");
        assertThat(client).isNotNull();
    }
}
