package ai.anomalousvectors.tools.burp.utils.config;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ExportFieldCatalogTest {

    @Test
    void traffic_catalog_has_burp_directory_with_leaf_children_not_burp_leaf() {
        ExportFieldCatalog.Node root = ExportFieldCatalog.catalogForIndex("traffic");
        ExportFieldCatalog.Node burp = childBySegment(root, "burp").orElseThrow();
        assertThat(burp.kind()).isEqualTo(ExportFieldCatalog.Kind.DIRECTORY);
        assertThat(burp.displayTitle()).isEqualTo("Burp");
        assertThat(leafPaths(burp)).contains("burp.reporting_tool", "burp.is_in_scope");
        assertThat(toggleableLeafPaths(root)).doesNotContain("burp");
    }

    @Test
    void traffic_catalog_has_websocket_directory_with_payload_and_discriminator_leaves() {
        ExportFieldCatalog.Node root = ExportFieldCatalog.catalogForIndex("traffic");
        ExportFieldCatalog.Node websocket = childBySegment(root, "websocket").orElseThrow();
        assertThat(websocket.kind()).isEqualTo(ExportFieldCatalog.Kind.DIRECTORY);
        assertThat(websocket.displayTitle()).isEqualTo("WebSocket");
        assertThat(leafPaths(websocket)).contains(
                "websocket.is_websocket",
                "websocket.direction",
                "websocket.payload.text",
                "websocket.payload.b64",
                "websocket.id",
                "websocket.message_id");
        assertThat(toggleableLeafPaths(root)).doesNotContain("websocket");
    }

    @Test
    void traffic_catalog_has_burp_repeater_leaves_from_mapping() {
        ExportFieldCatalog.Node root = ExportFieldCatalog.catalogForIndex("traffic");
        ExportFieldCatalog.Node burp = childBySegment(root, "burp").orElseThrow();
        ExportFieldCatalog.Node repeater = childBySegment(burp, "repeater").orElseThrow();
        assertThat(repeater.kind()).isEqualTo(ExportFieldCatalog.Kind.DIRECTORY);
        assertThat(leafPaths(repeater)).containsExactlyInAnyOrder("burp.repeater.tab_name", "burp.repeater.tab_group");
        assertThat(childBySegment(root, "repeater")).isEmpty();
    }

    @Test
    void findings_catalog_uses_plural_requests_responses_evidence_container() {
        ExportFieldCatalog.Node root = ExportFieldCatalog.catalogForIndex("findings");
        ExportFieldCatalog.Node node = findNodeByPath(root, "requests_responses.request.method")
                .orElseThrow();
        assertThat(node.kind()).isEqualTo(ExportFieldCatalog.Kind.TOGGLEABLE_LEAF);
        assertThat(toggleableLeafPaths(root))
                .contains("requests_responses.request.method")
                .doesNotContain("request_responses_missing", "request_responses.request.method");
    }

    @Test
    void catalog_toggleable_leaves_match_registry_toggleable_fields() {
        for (String index : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            List<String> fromCatalog = toggleableLeafPaths(ExportFieldCatalog.catalogForIndex(index));
            assertThat(fromCatalog)
                    .as("toggleable leaves for " + index)
                    .containsExactlyInAnyOrderElementsOf(ExportFieldRegistry.getToggleableFields(index));
        }
    }

    private static java.util.Optional<ExportFieldCatalog.Node> findNodeByPath(ExportFieldCatalog.Node parent, String path) {
        if (!parent.isDirectory()) {
            return path.equals(parent.path()) ? java.util.Optional.of(parent) : java.util.Optional.empty();
        }
        if (path.isEmpty()) {
            return java.util.Optional.of(parent);
        }
        for (ExportFieldCatalog.Node child : parent.children()) {
            if (path.equals(child.path()) || path.startsWith(child.path() + ".")) {
                java.util.Optional<ExportFieldCatalog.Node> nested = findNodeByPath(child, path);
                if (nested.isPresent()) {
                    return nested;
                }
            }
        }
        return java.util.Optional.empty();
    }

    private static java.util.Optional<ExportFieldCatalog.Node> childBySegment(ExportFieldCatalog.Node parent, String segment) {
        for (ExportFieldCatalog.Node child : parent.children()) {
            if (segment.equals(child.segment())) {
                return java.util.Optional.of(child);
            }
        }
        return java.util.Optional.empty();
    }

    private static List<String> leafPaths(ExportFieldCatalog.Node node) {
        List<String> paths = new ArrayList<>();
        collectLeafPaths(node, paths);
        return paths;
    }

    private static List<String> toggleableLeafPaths(ExportFieldCatalog.Node node) {
        List<String> paths = new ArrayList<>();
        collectToggleableLeafPaths(node, paths);
        return paths;
    }

    private static void collectLeafPaths(ExportFieldCatalog.Node node, List<String> paths) {
        if (!node.isDirectory()) {
            paths.add(node.path());
            return;
        }
        for (ExportFieldCatalog.Node child : node.children()) {
            collectLeafPaths(child, paths);
        }
    }

    private static void collectToggleableLeafPaths(ExportFieldCatalog.Node node, List<String> paths) {
        if (!node.isDirectory()) {
            if (node.kind() == ExportFieldCatalog.Kind.TOGGLEABLE_LEAF) {
                paths.add(node.path());
            }
            return;
        }
        for (ExportFieldCatalog.Node child : node.children()) {
            collectToggleableLeafPaths(child, paths);
        }
    }
}
