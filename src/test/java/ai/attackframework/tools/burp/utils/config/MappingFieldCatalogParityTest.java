package ai.attackframework.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Ensures mapping-discovered toggleable leaves stay aligned with the Fields panel catalog and registry.
 */
class MappingFieldCatalogParityTest {

    @Test
    void mappingToggleableLeaves_matchExportFieldRegistryForEveryIndex() {
        for (String index : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            List<String> fromMapping = MappingFieldCatalog.discoverToggleableLeaves(index);
            assertThat(fromMapping)
                    .as("mapping leaves for " + index)
                    .containsExactlyInAnyOrderElementsOf(ExportFieldRegistry.getToggleableFields(index));
        }
    }

    @Test
    void exportFieldCatalog_toggleableLeaves_existInMappingDiscovery() {
        for (String index : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            List<String> catalogLeaves = toggleableLeafPaths(ExportFieldCatalog.catalogForIndex(index));
            List<String> mappingLeaves = MappingFieldCatalog.discoverToggleableLeaves(index);
            assertThat(mappingLeaves)
                    .as("catalog vs mapping for " + index)
                    .containsAll(catalogLeaves);
        }
    }

    private static List<String> toggleableLeafPaths(ExportFieldCatalog.Node node) {
        List<String> paths = new ArrayList<>();
        collectToggleableLeaves(node, paths);
        return paths;
    }

    private static void collectToggleableLeaves(ExportFieldCatalog.Node node, List<String> paths) {
        if (node.kind() == ExportFieldCatalog.Kind.TOGGLEABLE_LEAF) {
            paths.add(node.path());
            return;
        }
        for (ExportFieldCatalog.Node child : node.children()) {
            collectToggleableLeaves(child, paths);
        }
    }
}
