package ai.anomalousvectors.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

class ConfigImportCatalogDataSourcesTest {

    @Test
    void compactDataSourcesForExport_nullWhenAllProfessionalSourcesSelected() {
        List<String> all = ConfigImportCatalog.allDataSourcesForEdition(false);
        assertThat(ConfigImportCatalog.compactDataSourcesForExport(all, false)).isNull();
        assertThat(ConfigImportCatalog.isAllDataSourcesSelected(all, false)).isTrue();
    }

    @Test
    void compactDataSourcesForExport_keepsPartialSelectionInOrder() {
        List<String> compacted = ConfigImportCatalog.compactDataSourcesForExport(
                List.of(ConfigKeys.SRC_TRAFFIC, ConfigKeys.SRC_SETTINGS), false);

        assertThat(compacted).containsExactly(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_TRAFFIC);
    }

    @Test
    void compactDataSourcesForExport_emptyListMeansExplicitNone() {
        assertThat(ConfigImportCatalog.compactDataSourcesForExport(List.of(), false)).isEmpty();
    }

    @Test
    void allDataSourcesForEdition_communityOmitsFindings() {
        assertThat(ConfigImportCatalog.allDataSourcesForEdition(true))
                .doesNotContain(ConfigKeys.SRC_FINDINGS)
                .contains(ConfigKeys.SRC_TRAFFIC);
    }

    @Test
    void compactDataSourceOptionsForExport_nullWhenAllBranchesAtDefault() {
        assertThat(ConfigImportCatalog.compactDataSourceOptionsForExport(
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                false)).isNull();
    }

    @Test
    void compactDataSourceOptionsForExport_keepsOnlyTrafficWhenIntruderDisabled() {
        List<String> trafficWithoutIntruder = ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES.stream()
                .filter(tool -> !"intruder".equals(tool))
                .toList();

        ConfigImportCatalog.CompactDataSourceOptions compact =
                ConfigImportCatalog.compactDataSourceOptionsForExport(
                        ConfigState.DEFAULT_SETTINGS_SUB,
                        trafficWithoutIntruder,
                        ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                        ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                        ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                        false);

        assertThat(compact).isNotNull();
        assertThat(compact.settings()).isNull();
        assertThat(compact.findings()).isNull();
        assertThat(compact.exporter()).isNull();
        assertThat(compact.exporterStatsIntervalSeconds()).isNull();
        assertThat(compact.traffic()).doesNotContain("intruder");
        assertThat(compact.traffic()).containsExactlyElementsOf(trafficWithoutIntruder);
    }
}
