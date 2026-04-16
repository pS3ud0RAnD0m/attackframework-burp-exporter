package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class IndexNamingTest {

    @Test
    void computeIndexBaseNames_includesToolOnlyWhenExporterSelected() {
        List<String> bases = IndexNaming.computeIndexBaseNames(List.of("traffic", "exporter"));

        String p = IndexNaming.INDEX_PREFIX;
        assertThat(bases).contains(p, p + "-traffic");
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
        List<String> out = IndexNaming.toJsonFileNames(List.of(p, p + "-traffic"));

        assertThat(out).containsExactlyInAnyOrder(
                p + ".json",
                p + "-traffic.json"
        );
    }

    @Test
    void toExportFileNames_includesSelectedFormatsForEachBase() {
        String p = IndexNaming.INDEX_PREFIX;
        List<String> out = IndexNaming.toExportFileNames(List.of(p, p + "-traffic"), true, true);

        assertThat(out).containsExactly(
                p + ".jsonl",
                p + ".ndjson",
                p + "-traffic.jsonl",
                p + "-traffic.ndjson"
        );
    }
}
