package ai.attackframework.tools.burp.utils.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JsonKeyOrderTest {

    private static final ObjectMapper M = new ObjectMapper();

    @Test
    void top_level_keys_are_in_deterministic_order() throws Exception {
        String json = Json.buildConfigJsonTyped(
                List.of("settings", "sitemap"),
                "custom",
                List.of("^foo$", "aaa", "bar.*"),
                List.of("regex", "string", "regex"),
                true, "/tmp/out",
                true, "http://localhost:9200"
        );

        JsonNode root = M.readTree(json);
        List<String> keys = new ArrayList<>();
        root.fields().forEachRemaining(e -> keys.add(e.getKey()));

        assertThat(keys).containsExactly("version", "dataSources", "scope", "sinks");
    }

    @Test
    void custom_scope_preserves_insertion_order_of_typed_entries() throws Exception {
        String json = Json.buildConfigJsonTyped(
                List.of("settings"),
                "custom",
                List.of("^foo$", "aaa", "bar.*"),
                List.of("regex", "string", "regex"),
                false, null,
                false, null
        );

        JsonNode custom = M.readTree(json).path("scope").path("custom");
        List<String> keys = new ArrayList<>();
        custom.fields().forEachRemaining(e -> keys.add(e.getKey()));

        // Keys reflect insertion order with counters applied at build time.
        assertThat(keys).containsExactly("regex1", "string1", "regex2");
    }
}
