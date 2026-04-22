package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.attackframework.tools.burp.utils.config.ConfigState;

class IndexNamingTest {

    @Test
    void computeIndexBaseNames_includesToolOnlyWhenExporterSelected() {
        List<String> bases = IndexNaming.computeIndexBaseNames(List.of("traffic", "exporter"));

        String p = IndexNaming.INDEX_PREFIX;
        assertThat(bases).contains(p + "-exporter", p + "-traffic");
    }

    @Test
    void computeIndexBaseNames_omitsToolWhenExporterNotSelected() {
        List<String> bases = IndexNaming.computeIndexBaseNames(List.of("traffic"));

        assertThat(bases).containsExactly(IndexNaming.INDEX_PREFIX + "-traffic");
    }

    @Test
    void toJsonFileNames_appendsDotJsonToEachBase() {
        // All base names should end with ".json"
        String p = IndexNaming.INDEX_PREFIX;
        List<String> out = IndexNaming.toJsonFileNames(List.of(p + "-exporter", p + "-traffic"));

        assertThat(out).containsExactlyInAnyOrder(
                p + "-exporter.json",
                p + "-traffic.json"
        );
    }

    @Test
    void toExportFileNames_includesSelectedFormatsForEachBase() {
        String p = IndexNaming.INDEX_PREFIX;
        List<String> out = IndexNaming.toExportFileNames(List.of(p + "-exporter", p + "-traffic"), true, true);

        assertThat(out).containsExactly(
                p + "-exporter.jsonl",
                p + "-exporter.ndjson",
                p + "-traffic.jsonl",
                p + "-traffic.ndjson"
        );
    }

    @Test
    void resolveAllConfiguredNames_usesGlobalBaseForAllIndexes() {
        ConfigState.State state = new ConfigState.State(
                List.of("exporter", "traffic"),
                "all",
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                "${now:yyyyMMdd}-attackframework-tool-burp",
                null);

        IndexNaming.ResolutionResult resolution = IndexNaming.resolveAllConfiguredNames(
                state,
                java.time.Instant.parse("2026-04-15T12:34:56Z"));

        assertThat(resolution.valid()).isTrue();
        assertThat(resolution.namesByKey().get("exporter")).isEqualTo("20260415-attackframework-tool-burp-exporter");
        assertThat(resolution.namesByKey().get("traffic")).isEqualTo("20260415-attackframework-tool-burp-traffic");
    }

    @Test
    void requireKnownIndexKey_legacyToolIndexName_mapsToExporter() {
        assertThat(IndexNaming.requireKnownIndexKey(IndexNaming.LEGACY_TOOL_INDEX_NAME))
                .isEqualTo("exporter");
        assertThat(IndexNaming.requireKnownIndexKey(IndexNaming.indexNameForShortName("exporter")))
                .isEqualTo("exporter");
    }

    @Test
    void requireKnownIndexKey_rejectsCustomPhysicalNames() {
        assertThatThrownBy(() -> IndexNaming.requireKnownIndexKey("custom-prefix-traffic"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("pass the logical index key explicitly");
    }

    @Test
    void validateBaseTemplate_matchesOpenSearchCriteriaAfterSuffixesAreApplied() {
        IndexNaming.BaseTemplateValidation validation = IndexNaming.validateBaseTemplateDetailed(
                "Attackframework Tool Burp",
                java.time.Instant.parse("2026-04-15T12:34:56Z"));

        assertThat(validation.valid()).isFalse();
        assertThat(validation.failingIndexKey()).isEqualTo("exporter");
        assertThat(validation.failingDisplayName()).isEqualTo("Exporter");
        assertThat(validation.failingResolvedName()).isEqualTo("Attackframework Tool Burp-exporter");
        assertThat(validation.error()).isEqualTo("must be lowercase.");
    }

    @Test
    void validateBaseTemplate_reportsLengthFailures_afterSuffixIsAppended() {
        String nearLimitBase = "a".repeat(247);

        IndexNaming.BaseTemplateValidation validation = IndexNaming.validateBaseTemplateDetailed(
                nearLimitBase,
                java.time.Instant.parse("2026-04-15T12:34:56Z"));

        assertThat(validation.valid()).isFalse();
        assertThat(validation.failingIndexKey()).isEqualTo("exporter");
        assertThat(validation.failingResolvedName()).isEqualTo(nearLimitBase + "-exporter");
        assertThat(validation.error()).contains("255-byte OpenSearch index-name limit");
    }
}
