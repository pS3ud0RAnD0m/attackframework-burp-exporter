package ai.attackframework.tools.burp.utils.opensearch;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the poison-pill behaviour: permanently rejected items are dropped (not re-queued), counted
 * via {@link ExportStats#recordPermanentDrop(String, long)}, and logged once; transient failures
 * pass through to the caller's re-queue list.
 */
class IndexingRetryCoordinatorPoisonPillTest {

    private final List<String> events = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);

    @BeforeEach
    void registerLogListener() {
        ExportStats.resetForTests();
        Logger.resetState();
        Logger.registerListener(listener);
    }

    @AfterEach
    void unregisterLogListener() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        events.clear();
    }

    @Test
    void permanentFailures_areDropped_andTransientFailuresReturnedForRetry() throws Exception {
        List<Map<String, Object>> batch = List.of(
                docFor("permanent-1"),
                docFor("transient-1"),
                docFor("permanent-2"),
                docFor("transient-2"));

        List<OpenSearchClientWrapper.FailedItem> failed = List.of(
                new OpenSearchClientWrapper.FailedItem(0, "mapper_parsing_exception", "immense term"),
                new OpenSearchClientWrapper.FailedItem(1, "es_rejected_execution_exception", "queue full"),
                new OpenSearchClientWrapper.FailedItem(2, "illegal_argument_exception", "nested limit exceeded"),
                new OpenSearchClientWrapper.FailedItem(3, "unavailable_shards_exception", "red"));

        List<Map<String, Object>> retryList = filterOnEdt(batch, failed, "test-index", "traffic");

        assertThat(retryList).extracting("marker").containsExactly("transient-1", "transient-2");
        assertThat(ExportStats.getPermanentDrops("traffic")).isEqualTo(2);
        assertThat(ExportStats.getTotalPermanentDrops()).isEqualTo(2);
        assertThat(events)
                .anySatisfy(e -> assertThat(e)
                        .contains("[OpenSearch] Dropped 2 permanently rejected document(s) from retry for index test-index"));
    }

    @Test
    void allPermanentFailures_returnsEmptyRetryList() throws Exception {
        List<Map<String, Object>> batch = List.of(docFor("a"), docFor("b"));
        List<OpenSearchClientWrapper.FailedItem> failed = List.of(
                new OpenSearchClientWrapper.FailedItem(0, "mapper_parsing_exception", "bad"),
                new OpenSearchClientWrapper.FailedItem(1, "strict_dynamic_mapping_exception", "bad"));

        List<Map<String, Object>> retryList = filterOnEdt(batch, failed, "sitemap-index", "sitemap");

        assertThat(retryList).isEmpty();
        assertThat(ExportStats.getPermanentDrops("sitemap")).isEqualTo(2);
    }

    @Test
    void missingFailureDetails_treatsEntireBatchAsTransient() throws Exception {
        List<Map<String, Object>> batch = List.of(docFor("a"), docFor("b"));

        List<Map<String, Object>> retryList = filterOnEdt(batch, List.of(), "findings-index", "findings");

        assertThat(retryList).containsExactlyElementsOf(batch);
        assertThat(ExportStats.getPermanentDrops("findings")).isZero();
    }

    @Test
    void outOfRangeIndices_areSkippedWithoutCrashing() throws Exception {
        List<Map<String, Object>> batch = List.of(docFor("a"));
        List<OpenSearchClientWrapper.FailedItem> failed = List.of(
                new OpenSearchClientWrapper.FailedItem(0, "mapper_parsing_exception", "bad"),
                new OpenSearchClientWrapper.FailedItem(5, "mapper_parsing_exception", "phantom"),
                new OpenSearchClientWrapper.FailedItem(-1, "mapper_parsing_exception", "phantom"));

        List<Map<String, Object>> retryList = filterOnEdt(batch, failed, "traffic-index", "traffic");

        assertThat(retryList).isEmpty();
        assertThat(ExportStats.getPermanentDrops("traffic")).isEqualTo(1);
    }

    /**
     * Runs {@link IndexingRetryCoordinator#filterTransientFailures} on the EDT so that any
     * listener dispatch from {@code logErrorPanelOnly} happens synchronously before assertions.
     */
    private static List<Map<String, Object>> filterOnEdt(
            List<Map<String, Object>> batch,
            List<OpenSearchClientWrapper.FailedItem> failed,
            String indexName,
            String indexKey) throws Exception {
        AtomicReference<List<Map<String, Object>>> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() ->
                ref.set(IndexingRetryCoordinator.filterTransientFailures(batch, failed, indexName, indexKey)));
        return ref.get();
    }

    private static Map<String, Object> docFor(String marker) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("marker", marker);
        return doc;
    }
}
