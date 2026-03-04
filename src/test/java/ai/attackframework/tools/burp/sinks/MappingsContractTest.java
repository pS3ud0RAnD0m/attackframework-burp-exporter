package ai.attackframework.tools.burp.sinks;

import java.io.InputStream;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract tests for the OpenSearch index mapping resources.
 * Ensures required JSON files are present, parseable, and contain the structure
 * that OpenSearchSink.createIndexFromResource() expects: both "settings" and "mappings"
 * (with non-empty "mappings.properties").
 */
class MappingsContractTest {

    private static final List<String> MAPPING_FILES = List.of(
            "findings.json",
            "settings.json",
            "sitemap.json",
            "tool.json",
            "traffic.json"
    );

    private static final String RESOURCE_ROOT = "/opensearch/mappings/";

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void mappingFiles_exist_parse_andContainRequiredKeys() throws Exception {
        for (String file : MAPPING_FILES) {
            String path = RESOURCE_ROOT + file;

            try (InputStream in = getClass().getResourceAsStream(path)) {
                assertThat(in)
                        .withFailMessage("Resource not found on classpath: %s", path)
                        .isNotNull();

                JsonNode root = mapper.readTree(in);

                // Required by OpenSearchSink: presence of both keys
                assertThat(root.has("settings"))
                        .withFailMessage("Missing 'settings' in %s", file)
                        .isTrue();
                JsonNode settings = root.get("settings");
                assertThat(settings != null && settings.isObject())
                        .withFailMessage("'settings' must be a JSON object (can be empty) in %s", file)
                        .isTrue();

                assertThat(root.has("mappings"))
                        .withFailMessage("Missing 'mappings' in %s", file)
                        .isTrue();
                JsonNode mappings = root.get("mappings");
                assertThat(mappings.isObject())
                        .withFailMessage("'mappings' must be a JSON object in %s", file)
                        .isTrue();

                assertThat(mappings.has("properties"))
                        .withFailMessage("Missing 'mappings.properties' in %s", file)
                        .isTrue();
                JsonNode properties = mappings.get("properties");
                assertThat(properties.isObject())
                        .withFailMessage("'mappings.properties' must be a JSON object in %s", file)
                        .isTrue();
                assertThat(properties.size())
                        .withFailMessage("'mappings.properties' is empty in %s", file)
                        .isGreaterThan(0);
            }
        }
    }

    @Test
    void trafficMapping_containsExpectedWebSocketFields() throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "traffic.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode props = root.path("mappings").path("properties");

            assertThat(props.has("websocket_id")).isTrue();
            assertThat(props.has("ws_direction")).isTrue();
            assertThat(props.has("ws_message_type")).isTrue();
            assertThat(props.has("ws_payload")).isTrue();
            assertThat(props.has("ws_payload_text")).isTrue();
            assertThat(props.has("ws_payload_length")).isTrue();
            assertThat(props.has("ws_edited")).isTrue();
            assertThat(props.has("ws_edited_payload")).isTrue();
            assertThat(props.has("ws_upgrade_request")).isTrue();
            assertThat(props.has("ws_time")).isTrue();
            assertThat(props.has("ws_message_id")).isTrue();
        }
    }

    @Test
    void bodyTextFields_useOffsets_acrossExportedHttpDocs() throws Exception {
        assertTextOffsetsOnRequestAndResponseBodies("traffic.json");
        assertTextOffsetsOnRequestAndResponseBodies("sitemap.json");

        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "findings.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode rr = root.path("mappings")
                    .path("properties")
                    .path("request_responses")
                    .path("properties");

            assertThat(rr.path("request").path("properties").path("body").path("properties").path("text")
                    .path("index_options").asText()).isEqualTo("offsets");
            assertThat(rr.path("response").path("properties").path("body").path("properties").path("text")
                    .path("index_options").asText()).isEqualTo("offsets");
        }
    }

    @Test
    void responseBodyDerivedFields_areNestedUnderBody_inTrafficAndSitemap() throws Exception {
        assertResponseDerivedFieldsNested("traffic.json");
        assertResponseDerivedFieldsNested("sitemap.json");
    }

    @Test
    void bodyMetadata_areNestedUnderBody_acrossHttpDocs() throws Exception {
        assertBodyMetadataNested("traffic.json");
        assertBodyMetadataNested("sitemap.json");

        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "findings.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode rr = root.path("mappings")
                    .path("properties")
                    .path("request_responses")
                    .path("properties");

            JsonNode rrReqProps = rr.path("request").path("properties");
            JsonNode rrReqBodyProps = rrReqProps.path("body").path("properties");
            assertThat(rrReqBodyProps.has("length")).isTrue();
            assertThat(rrReqBodyProps.has("offset")).isTrue();
            assertThat(rrReqProps.has("body_length")).isFalse();
            assertThat(rrReqProps.has("body_offset")).isFalse();

            JsonNode rrRespProps = rr.path("response").path("properties");
            JsonNode rrRespBodyProps = rrRespProps.path("body").path("properties");
            assertThat(rrRespBodyProps.has("length")).isTrue();
            assertThat(rrRespBodyProps.has("offset")).isTrue();
            assertThat(rrRespProps.has("body_length")).isFalse();
            assertThat(rrRespProps.has("body_offset")).isFalse();
        }
    }

    @Test
    void headers_areOrganizedUnderHeadersParent_acrossHttpDocs() throws Exception {
        assertHeadersHierarchy("traffic.json");
        assertHeadersHierarchy("sitemap.json");

        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + "findings.json")) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode rr = root.path("mappings")
                    .path("properties")
                    .path("request_responses")
                    .path("properties");

            JsonNode rrReqHeaders = rr.path("request").path("properties").path("headers").path("properties");
            assertThat(rrReqHeaders.has("full")).isTrue();
            assertThat(rr.path("request").path("properties").has("header_names")).isFalse();

            JsonNode rrRespHeaders = rr.path("response").path("properties").path("headers").path("properties");
            assertThat(rrRespHeaders.has("full")).isTrue();
            assertThat(rrRespHeaders.has("names")).isTrue();
            assertThat(rrRespHeaders.has("etag")).isTrue();
            assertThat(rrRespHeaders.has("last_modified")).isTrue();
            assertThat(rrRespHeaders.has("content_location")).isTrue();
            assertThat(rr.path("response").path("properties").has("header_names")).isFalse();
            assertThat(rr.path("response").path("properties").has("etag_header")).isFalse();
            assertThat(rr.path("response").path("properties").has("last_modified_header")).isFalse();
            assertThat(rr.path("response").path("properties").has("content_location")).isFalse();
        }
    }

    private void assertTextOffsetsOnRequestAndResponseBodies(String mappingFile) throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + mappingFile)) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode props = root.path("mappings").path("properties");

            assertThat(props.path("request").path("properties").path("body").path("properties").path("text")
                    .path("index_options").asText()).isEqualTo("offsets");
            assertThat(props.path("response").path("properties").path("body").path("properties").path("text")
                    .path("index_options").asText()).isEqualTo("offsets");
            assertThat(props.path("response").path("properties").path("body").path("properties").path("visible_text")
                    .path("index_options").asText()).isEqualTo("offsets");
        }
    }

    private void assertResponseDerivedFieldsNested(String mappingFile) throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + mappingFile)) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode responseProps = root.path("mappings").path("properties").path("response").path("properties");
            JsonNode bodyProps = responseProps.path("body").path("properties");

            assertThat(bodyProps.has("page_title")).isTrue();
            assertThat(bodyProps.has("visible_text")).isTrue();
            assertThat(bodyProps.has("word_count")).isTrue();
            assertThat(bodyProps.has("visible_word_count")).isTrue();
            assertThat(bodyProps.has("line_count")).isTrue();
            assertThat(bodyProps.has("anchor_labels")).isTrue();
            assertThat(bodyProps.has("tag_names")).isTrue();
            assertThat(bodyProps.has("div_ids")).isTrue();
            assertThat(bodyProps.has("css_classes")).isTrue();

            assertThat(responseProps.has("page_title")).isFalse();
            assertThat(responseProps.has("visible_text")).isFalse();
            assertThat(responseProps.has("word_count")).isFalse();
            assertThat(responseProps.has("visible_word_count")).isFalse();
            assertThat(responseProps.has("line_count")).isFalse();
            assertThat(responseProps.has("anchor_labels")).isFalse();
            assertThat(responseProps.has("tag_names")).isFalse();
            assertThat(responseProps.has("div_ids")).isFalse();
            assertThat(responseProps.has("css_classes")).isFalse();
        }
    }

    private void assertHeadersHierarchy(String mappingFile) throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + mappingFile)) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode props = root.path("mappings").path("properties");

            JsonNode requestProps = props.path("request").path("properties");
            JsonNode requestHeaders = requestProps.path("headers").path("properties");
            assertThat(requestHeaders.has("full")).isTrue();

            JsonNode responseProps = props.path("response").path("properties");
            JsonNode responseHeaders = responseProps.path("headers").path("properties");
            assertThat(responseHeaders.has("full")).isTrue();
            assertThat(responseHeaders.has("names")).isTrue();
            assertThat(responseHeaders.has("etag")).isTrue();
            assertThat(responseHeaders.has("last_modified")).isTrue();
            assertThat(responseHeaders.has("content_location")).isTrue();

            assertThat(responseProps.has("header_names")).isFalse();
            assertThat(responseProps.has("etag_header")).isFalse();
            assertThat(responseProps.has("last_modified_header")).isFalse();
            assertThat(responseProps.has("content_location")).isFalse();
        }
    }

    private void assertBodyMetadataNested(String mappingFile) throws Exception {
        try (InputStream in = getClass().getResourceAsStream(RESOURCE_ROOT + mappingFile)) {
            assertThat(in).isNotNull();
            JsonNode root = mapper.readTree(in);
            JsonNode props = root.path("mappings").path("properties");

            JsonNode requestProps = props.path("request").path("properties");
            JsonNode requestBody = requestProps.path("body").path("properties");
            assertThat(requestBody.has("length")).isTrue();
            assertThat(requestBody.has("offset")).isTrue();
            assertThat(requestProps.has("body_length")).isFalse();
            assertThat(requestProps.has("body_offset")).isFalse();

            JsonNode responseProps = props.path("response").path("properties");
            JsonNode responseBody = responseProps.path("body").path("properties");
            assertThat(responseBody.has("length")).isTrue();
            assertThat(responseBody.has("offset")).isTrue();
            assertThat(responseProps.has("body_length")).isFalse();
            assertThat(responseProps.has("body_offset")).isFalse();
        }
    }
}
