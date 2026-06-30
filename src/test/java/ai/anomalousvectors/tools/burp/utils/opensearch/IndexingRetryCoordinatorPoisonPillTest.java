package ai.anomalousvectors.tools.burp.utils.opensearch;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
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
    public void registerLogListener() {
        ExportStats.resetForTests();
        Logger.resetState();
        Logger.registerListener(listener);
    }

    @AfterEach
    public void unregisterLogListener() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        events.clear();
    }

    @Test
    void permanentFailures_areDropped_andTransientFailuresReturnedForRetry() throws Exception {
        List<PreparedExportDocument> batch = preparedBatch(
                "traffic-index", "traffic",
                List.of(
                        docFor("permanent-1"),
                        docFor("transient-1"),
                        docFor("permanent-2"),
                        docFor("transient-2")));

        List<OpenSearchClientWrapper.FailedItem> failed = List.of(
                new OpenSearchClientWrapper.FailedItem(0, "mapper_parsing_exception", "immense term"),
                new OpenSearchClientWrapper.FailedItem(1, "es_rejected_execution_exception", "queue full"),
                new OpenSearchClientWrapper.FailedItem(2, "illegal_argument_exception", "nested limit exceeded"),
                new OpenSearchClientWrapper.FailedItem(3, "unavailable_shards_exception", "red"));

        List<PreparedExportDocument> retryList = filterOnEdt(batch, failed, "test-index", "traffic");

        assertThat(retryList).containsExactly(batch.get(1), batch.get(3));
        assertThat(ExportStats.getPermanentDrops("traffic")).isEqualTo(2);
        assertThat(ExportStats.getTotalPermanentDrops()).isEqualTo(2);
        assertThat(events)
                .anySatisfy(e -> assertThat(e)
                        .contains("[OpenSearch] Dropped 2 permanently rejected document(s) from retry for index test-index"));
    }

    @Test
    void allPermanentFailures_returnsEmptyRetryList() throws Exception {
        List<PreparedExportDocument> batch = preparedBatch(
                "sitemap-index", "sitemap", List.of(docFor("a"), docFor("b")));
        List<OpenSearchClientWrapper.FailedItem> failed = List.of(
                new OpenSearchClientWrapper.FailedItem(0, "mapper_parsing_exception", "bad"),
                new OpenSearchClientWrapper.FailedItem(1, "strict_dynamic_mapping_exception", "bad"));

        List<PreparedExportDocument> retryList = filterOnEdt(batch, failed, "sitemap-index", "sitemap");

        assertThat(retryList).isEmpty();
        assertThat(ExportStats.getPermanentDrops("sitemap")).isEqualTo(2);
    }

    @Test
    void missingFailureDetails_treatsEntireBatchAsTransient() throws Exception {
        List<PreparedExportDocument> batch = preparedBatch(
                "findings-index", "findings", List.of(docFor("a"), docFor("b")));

        List<PreparedExportDocument> retryList = filterOnEdt(batch, List.of(), "findings-index", "findings");

        assertThat(retryList).containsExactlyElementsOf(batch);
        assertThat(ExportStats.getPermanentDrops("findings")).isZero();
    }

    @Test
    void outOfRangeIndices_areSkippedWithoutCrashing() throws Exception {
        List<PreparedExportDocument> batch = preparedBatch("traffic-index", "traffic", List.of(docFor("a")));
        List<OpenSearchClientWrapper.FailedItem> failed = List.of(
                new OpenSearchClientWrapper.FailedItem(0, "mapper_parsing_exception", "bad"),
                new OpenSearchClientWrapper.FailedItem(5, "mapper_parsing_exception", "phantom"),
                new OpenSearchClientWrapper.FailedItem(-1, "mapper_parsing_exception", "phantom"));

        List<PreparedExportDocument> retryList = filterOnEdt(batch, failed, "traffic-index", "traffic");

        assertThat(retryList).isEmpty();
        assertThat(ExportStats.getPermanentDrops("traffic")).isEqualTo(1);
    }

    /**
     * Runs {@link IndexingRetryCoordinator#filterTransientFailures} on the EDT so that any
     * listener dispatch from {@code logErrorPanelOnly} happens synchronously before assertions.
     */
    private static List<PreparedExportDocument> filterOnEdt(
            List<PreparedExportDocument> batch,
            List<OpenSearchClientWrapper.FailedItem> failed,
            String indexName,
            String indexKey) throws Exception {
        AtomicReference<List<PreparedExportDocument>> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() ->
                ref.set(IndexingRetryCoordinator.filterTransientFailures(batch, failed, indexName, indexKey)));
        return ref.get();
    }

    private static Map<String, Object> docFor(String marker) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("marker", marker);
        return doc;
    }

    private static List<PreparedExportDocument> preparedBatch(
            String indexName,
            String indexKey,
            List<Map<String, Object>> documents) {
        return documents.stream()
                .map(document -> ExportDocumentIdentity.prepare(indexName, indexKey, document))
                .toList();
    }
}
