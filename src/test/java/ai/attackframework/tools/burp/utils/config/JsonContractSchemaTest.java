package ai.attackframework.tools.burp.utils.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

class JsonContractSchemaTest {

    @Test
    void example_fixture_conforms_to_sink_contract_artifact() throws IOException {
        JsonNode contract = readJsonResource("/contracts/exported-config-contract.json");
        JsonNode fixture = Json.MAPPER.readTree(readTextResource("/config/example-exported-config.json")
                .replace("${VERSION}", "test-version"));

        assertConformsToContract(fixture, contract);
    }

    @Test
    void build_outputs_sink_contract_for_each_auth_type() throws IOException {
        JsonNode contract = readJsonResource("/contracts/exported-config-contract.json");
        for (String authType : stringList(contract.path("sinks").path("openSearch").path("auth").path("allowedTypes"))) {
            String json = ConfigJsonMapper.build(stateForAuthType(authType));
            JsonNode root = Json.MAPPER.readTree(json);
            assertConformsToContract(root, contract);
            assertThat(root.path("sinks").path("openSearch").path("auth").path("type").asText()).isEqualTo(authType);
        }
    }

    private static void assertConformsToContract(JsonNode root, JsonNode contract) {
        assertThat(root.isObject()).isTrue();
        assertThat(fieldNames(root)).containsAll(stringList(contract.path("requiredTopLevelKeys")));

        JsonNode sinks = root.path("sinks");
        assertThat(sinks.isObject()).isTrue();
        assertThat(fieldNames(sinks)).containsAll(stringList(contract.path("sinks").path("requiredKeys")));

        JsonNode files = sinks.path("files");
        assertAllowedKeys(files, stringList(contract.path("sinks").path("files").path("allowedKeys")));
        JsonNode limits = files.path("limits");
        assertAllowedKeys(limits, stringList(contract.path("sinks").path("files").path("limits").path("allowedKeys")));
        assertThat(stringList(files.path("formats")))
                .allMatch(stringList(contract.path("sinks").path("files").path("allowedFormats"))::contains);

        JsonNode openSearch = sinks.path("openSearch");
        assertAllowedKeys(openSearch, stringList(contract.path("sinks").path("openSearch").path("allowedKeys")));
        JsonNode auth = openSearch.path("auth");
        assertAllowedKeys(auth, stringList(contract.path("sinks").path("openSearch").path("auth").path("allowedKeys")));

        String authType = auth.path("type").asText(ConfigState.DEFAULT_OPEN_SEARCH_AUTH_TYPE);
        List<String> allowedTypes = stringList(contract.path("sinks").path("openSearch").path("auth").path("allowedTypes"));
        assertThat(allowedTypes).contains(authType);

        List<String> allowedFieldsForType = stringList(contract.path("sinks").path("openSearch").path("auth")
                .path("allowedFieldsByType").path(authType));
        for (String field : List.of("username", "apiKeyId", "certPath", "certKeyPath")) {
            if (auth.has(field)) {
                assertThat(allowedFieldsForType).contains(field);
            }
        }

        JsonNode pinned = openSearch.path("pinnedTlsCertificate");
        assertAllowedKeys(pinned, stringList(contract.path("sinks").path("openSearch").path("pinnedTlsCertificate")
                .path("allowedKeys")));
    }

    private static void assertAllowedKeys(JsonNode node, List<String> allowedKeys) {
        assertThat(node.isObject()).isTrue();
        assertThat(fieldNames(node)).allMatch(allowedKeys::contains);
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        for (Iterator<String> it = node.fieldNames(); it.hasNext(); ) {
            names.add(it.next());
        }
        return names;
    }

    private static List<String> stringList(JsonNode arrayNode) {
        List<String> values = new ArrayList<>();
        if (!arrayNode.isArray()) {
            return values;
        }
        for (JsonNode node : arrayNode) {
            if (node.isTextual()) {
                values.add(node.asText());
            }
        }
        return values;
    }

    private static JsonNode readJsonResource(String path) throws IOException {
        return Json.MAPPER.readTree(readTextResource(path));
    }

    private static String readTextResource(String path) throws IOException {
        try (InputStream in = JsonContractSchemaTest.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IOException("Missing test resource: " + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static ConfigState.State stateForAuthType(String authType) {
        return new ConfigState.State(
                List.of("exporter", "settings"),
                "all",
                List.of(),
                new ConfigState.Sinks(
                        true,
                        "C:/Burp/exports",
                        true,
                        true,
                        true,
                        5d,
                        true,
                        95,
                        true,
                        "https://opensearch.example:9200",
                        "stale-basic-user",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_PINNED,
                        new ConfigState.OpenSearchOptions(
                                authType,
                                "kid-1",
                                "certs/client.pem",
                                "certs/client-key.pem",
                                "certs/opensearch-ca.pem",
                                "abcd1234",
                                "QUJDREVGRw==")),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                "${now:yyyyMMdd}-attackframework-tool-burp",
                null);
    }
}
