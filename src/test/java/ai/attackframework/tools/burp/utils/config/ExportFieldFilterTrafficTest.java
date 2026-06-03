package ai.attackframework.tools.burp.utils.config;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ExportFieldFilterTrafficTest {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    void restoreRuntimeConfig() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void filterTraffic_withAllFieldsEnabled_preservesBurpReporterAndRepeaterMetadata() {
        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> repeater = new LinkedHashMap<>();
        repeater.put("tab_name", "Manual Tab");
        repeater.put("tab_group", "Manual Group");
        doc.put("burp", new LinkedHashMap<>(Map.of(
                "reporting_tool", "Repeater",
                "is_in_scope", true,
                "repeater", repeater)));
        doc.put("request", new LinkedHashMap<>(Map.of("url", "https://example.test/repeater/live")));
        doc.put("meta", new LinkedHashMap<>(Map.of("schema_version", "test")));

        Map<String, Object> filtered = ExportFieldFilter.filterDocument(doc, "traffic");

        assertThat(filtered).containsKey("meta");
        assertThat(filtered.get("burp")).isInstanceOf(Map.class);
        Map<?, ?> burp = (Map<?, ?>) filtered.get("burp");
        assertThat(burp.get("reporting_tool")).isEqualTo("Repeater");
        assertThat(burp.get("is_in_scope")).isEqualTo(true);
        Map<?, ?> filteredRepeater = (Map<?, ?>) burp.get("repeater");
        assertThat(filteredRepeater.get("tab_name")).isEqualTo("Manual Tab");
        assertThat(filteredRepeater.get("tab_group")).isEqualTo("Manual Group");
    }

    @Test
    void filterTraffic_withAllFieldsEnabled_preservesNestedArrayContainers() {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("url", "https://example.test/path");
        request.put("header", Map.of("host", "example.test"));
        request.put("parameters", List.of(Map.of("name", "q", "type", "URL", "value", "one")));
        request.put("body", Map.of("markers", List.of(Map.of("start_inclusive", 0, "end_exclusive", 3))));
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("request", request);
        doc.put("meta", new LinkedHashMap<>(Map.of("schema_version", "test")));

        Map<String, Object> filtered = ExportFieldFilter.filterDocument(doc, "traffic");

        assertThat(filtered.get("request")).isInstanceOf(Map.class);
        Map<?, ?> filteredRequest = (Map<?, ?>) filtered.get("request");
        assertThat(filteredRequest.containsKey("header")).isTrue();
        assertThat(filteredRequest.containsKey("parameters")).isTrue();
        assertThat(filteredRequest.containsKey("markers")).isFalse();
        assertThat(filteredRequest.get("header")).isEqualTo(request.get("header"));
        assertThat(filteredRequest.get("parameters")).isEqualTo(request.get("parameters"));
        assertThat(filteredRequest.get("body")).isEqualTo(request.get("body"));
    }

    @Test
    void filterTraffic_withDynamicHeaderSelection_preservesAllHeaderFields() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                Map.of("traffic", Set.of("request.header"))));

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("url", "https://example.test/path");
        request.put("header", Map.of(
                "host", "example.test",
                "cookie", "session=secret"));
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("request", request);
        doc.put("meta", new LinkedHashMap<>(Map.of("schema_version", "test")));

        Map<String, Object> filtered = ExportFieldFilter.filterDocument(doc, "traffic");

        Map<?, ?> filteredRequest = (Map<?, ?>) filtered.get("request");
        assertThat(filteredRequest.get("header")).isEqualTo(request.get("header"));
        assertThat(filteredRequest.containsKey("url")).isFalse();
    }

    @Test
    void filterTraffic_withSelectedNestedResponseField_preservesExplicitNullResponse() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy_websocket"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                Map.of("traffic", Set.of("response.status.code"))));

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("response", null);
        doc.put("meta", new LinkedHashMap<>(Map.of("schema_version", "test")));

        Map<String, Object> filtered = ExportFieldFilter.filterDocument(doc, "traffic");

        assertThat(filtered).containsKey("response");
        assertThat(filtered.get("response")).isNull();
    }

    @Test
    void filterTraffic_withPartialNestedArraySelection_filtersListElementSiblings() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                Map.of("traffic", Set.of("request.parameters.name"))));

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("parameters", List.of(
                Map.of("name", "q", "type", "URL", "value", "one"),
                Map.of("name", "token", "type", "COOKIE", "value", "secret")));
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("request", request);
        doc.put("meta", new LinkedHashMap<>(Map.of("schema_version", "test")));

        Map<String, Object> filtered = ExportFieldFilter.filterDocument(doc, "traffic");

        Map<?, ?> filteredRequest = (Map<?, ?>) filtered.get("request");
        List<?> parameters = (List<?>) filteredRequest.get("parameters");
        assertThat(parameters).hasSize(2);
        Map<?, ?> firstParameter = (Map<?, ?>) parameters.get(0);
        Map<?, ?> secondParameter = (Map<?, ?>) parameters.get(1);
        assertThat(firstParameter.get("name")).isEqualTo("q");
        assertThat(firstParameter.containsKey("value")).isFalse();
        assertThat(secondParameter.get("name")).isEqualTo("token");
        assertThat(secondParameter.containsKey("value")).isFalse();
    }

    @Test
    void filterFindings_requestsResponses_omitsPairsWithNoEnabledNestedContent() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_FINDINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                Map.of("findings", Set.of("requests_responses.request.url"))));

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("requests_responses", List.of(
                Map.of("request", Map.of("url", "https://example.test/one")),
                Map.of("request", Map.of("method", "GET")),
                Map.of("response", Map.of("status", Map.of("code", 200)))));
        doc.put("meta", new LinkedHashMap<>(Map.of("schema_version", "test")));

        Map<String, Object> filtered = ExportFieldFilter.filterDocument(doc, "findings");

        List<?> pairs = (List<?>) filtered.get("requests_responses");
        assertThat(pairs).hasSize(1);
        Map<?, ?> pair = (Map<?, ?>) pairs.get(0);
        Map<?, ?> request = (Map<?, ?>) pair.get("request");
        assertThat(request.get("url")).isEqualTo("https://example.test/one");
        assertThat(request.containsKey("method")).isFalse();
    }

    @Test
    void filterTraffic_withSparseNestedArraySelection_keepsOnlyElementsWithEnabledFields() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                Map.of("traffic", Set.of("request.parameters.name", "request.parameters.value"))));

        Map<String, Object> request = new LinkedHashMap<>();
        Map<String, Object> nullableParameter = new LinkedHashMap<>();
        nullableParameter.put("name", "nullable");
        nullableParameter.put("value", null);
        request.put("parameters", List.of(
                Map.of("name", "q", "extra", "ignored"),
                new LinkedHashMap<>(Map.of("value", "application/json", "extra", "ignored")),
                nullableParameter));
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("request", request);
        doc.put("meta", new LinkedHashMap<>(Map.of("schema_version", "test")));

        Map<String, Object> filtered = ExportFieldFilter.filterDocument(doc, "traffic");

        Map<?, ?> filteredRequest = (Map<?, ?>) filtered.get("request");
        List<?> parameters = (List<?>) filteredRequest.get("parameters");
        assertThat(parameters).hasSize(3);
        Map<?, ?> firstParameter = (Map<?, ?>) parameters.get(0);
        Map<?, ?> secondParameter = (Map<?, ?>) parameters.get(1);
        Map<?, ?> thirdParameter = (Map<?, ?>) parameters.get(2);
        assertThat(firstParameter.get("name")).isEqualTo("q");
        assertThat(firstParameter.containsKey("value")).isFalse();
        assertThat(secondParameter.get("value")).isEqualTo("application/json");
        assertThat(secondParameter.containsKey("name")).isFalse();
        assertThat(thirdParameter.get("name")).isEqualTo("nullable");
        assertThat(thirdParameter.containsKey("value")).isTrue();
        assertThat(thirdParameter.get("value")).isNull();
    }
}
