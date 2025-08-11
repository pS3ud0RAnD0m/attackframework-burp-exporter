package ai.attackframework.tools.burp.sinks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

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
}
