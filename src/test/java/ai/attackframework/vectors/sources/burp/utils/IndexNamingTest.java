package ai.attackframework.vectors.sources.burp.utils;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class IndexNamingTest {

    @Test
    void computeIndexBaseNames_includesPrefixAndTrafficWhenSelected() {
        // When we request "traffic", expect base prefix plus traffic-specific index
        List<String> bases = IndexNaming.computeIndexBaseNames(List.of("traffic"));

        String p = IndexNaming.INDEX_PREFIX;
        assertThat(bases).contains(p);
        assertThat(bases).contains(p + "-traffic");
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
}
