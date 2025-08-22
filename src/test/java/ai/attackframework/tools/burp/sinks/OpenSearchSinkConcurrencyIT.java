package ai.attackframework.tools.burp.sinks;

import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Concurrency smoke test: creating multiple indices in parallel should not deadlock or throw.
 */
@Tag("integration")
class OpenSearchSinkConcurrencyIT {

    private static final String BASE_URL = "http://opensearch.url:9200";

    // Standard short names
    private static final List<String> SOURCES = List.of("sitemap", "findings", "traffic", "settings", "tool");

    // Expected full names for each short name
    private static final Map<String, String> EXPECTED_NAMES = Map.of(
            "tool", "attackframework-tool-burp",
            "sitemap", "attackframework-tool-burp-sitemap",
            "findings", "attackframework-tool-burp-findings",
            "settings", "attackframework-tool-burp-settings",
            "traffic", "attackframework-tool-burp-traffic"
    );

    @Test
    void createIndexes_concurrently_completes_withoutDeadlock() throws Exception {
        try (ExecutorService pool = Executors.newFixedThreadPool(SOURCES.size())) {
            List<Callable<IndexResult>> tasks = SOURCES.stream()
                    .map(shortName -> (Callable<IndexResult>) () ->
                            OpenSearchSink.createIndexFromResource(BASE_URL, shortName))
                    .toList();

            List<Future<IndexResult>> results = pool.invokeAll(tasks);

            for (Future<IndexResult> f : results) {
                IndexResult res;
                try {
                    res = f.get();
                } catch (ExecutionException e) {
                    throw new AssertionError("Task threw exception", e.getCause());
                }
                String expectedFull = EXPECTED_NAMES.get(res.shortName());
                assertThat(res.fullName()).isEqualTo(expectedFull);
                assertThat(res.status()).isIn(IndexResult.Status.CREATED, IndexResult.Status.EXISTS);
            }
        }
    }
}
