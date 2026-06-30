package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class BulkNdjsonResponseParserTest {

    @Test
    void parse_classifiesCreatedUpdatedAndNoop() {
        String body = """
                {"items":[
                  {"index":{"_index":"traffic","_id":"1","status":201,"result":"created"}},
                  {"index":{"_index":"traffic","_id":"2","status":200,"result":"updated"}},
                  {"index":{"_index":"traffic","_id":"3","status":200,"result":"noop"}}
                ]}
                """;

        BulkNdjsonResponseParser.ParsedBulk parsed = BulkNdjsonResponseParser.parse(body, "traffic");

        assertThat(parsed.breakdown().created()).isEqualTo(1);
        assertThat(parsed.breakdown().updated()).isEqualTo(1);
        assertThat(parsed.breakdown().noop()).isEqualTo(1);
        assertThat(parsed.successCount()).isEqualTo(3);
        assertThat(parsed.breakdown().exportedCount()).isEqualTo(2);
    }
}
