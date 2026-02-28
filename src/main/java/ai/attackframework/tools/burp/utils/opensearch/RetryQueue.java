package ai.attackframework.tools.burp.utils.opensearch;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Per-index bounded queues for failed OpenSearch index operations.
 * When a push fails, documents can be offered to the queue; a drain thread
 * later retries them. When the queue is full, new documents are rejected.
 */
public final class RetryQueue {

    private final int maxSizePerIndex;
    private final ConcurrentHashMap<String, BlockingQueue<Map<String, Object>>> queues = new ConcurrentHashMap<>();

    public RetryQueue(int maxSizePerIndex) {
        this.maxSizePerIndex = maxSizePerIndex;
    }

    /**
     * Offers a single document to the queue for the given index.
     *
     * @param indexName full index name (e.g. attackframework-tool-burp-traffic)
     * @param document  document to retry later
     * @return true if accepted, false if queue full
     */
    public boolean offer(String indexName, Map<String, Object> document) {
        BlockingQueue<Map<String, Object>> q = queueFor(indexName);
        return q.offer(document);
    }

    /**
     * Offers multiple documents to the queue for the given index.
     * Stops at first failure (queue full); earlier docs may have been added.
     *
     * @param indexName full index name
     * @param documents documents to retry later
     * @return number of documents actually accepted (0 to documents.size())
     */
    public int offerAll(String indexName, List<Map<String, Object>> documents) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        BlockingQueue<Map<String, Object>> q = queueFor(indexName);
        int added = 0;
        for (Map<String, Object> doc : documents) {
            if (!q.offer(doc)) {
                return added;
            }
            added++;
        }
        return added;
    }

    /**
     * Removes up to maxSize documents from the queue for the given index.
     *
     * @param indexName full index name
     * @param maxSize   maximum number of documents to poll
     * @return list of documents (may be empty, never null)
     */
    public List<Map<String, Object>> pollBatch(String indexName, int maxSize) {
        BlockingQueue<Map<String, Object>> q = queues.get(indexName);
        if (q == null) {
            return List.of();
        }
        List<Map<String, Object>> batch = new ArrayList<>(Math.min(maxSize, q.size()));
        q.drainTo(batch, maxSize);
        return batch;
    }

    /**
     * Returns the current number of documents queued for the given index.
     */
    public int size(String indexName) {
        BlockingQueue<Map<String, Object>> q = queues.get(indexName);
        return q == null ? 0 : q.size();
    }

    /**
     * Returns true if the queue for the given index is empty or absent.
     */
    public boolean isEmpty(String indexName) {
        return size(indexName) == 0;
    }

    /**
     * Returns true if all known queues are empty.
     */
    public boolean allEmpty() {
        return queues.values().stream().allMatch(BlockingQueue::isEmpty);
    }

    /**
     * Returns total number of queued documents across all indexes (for logging).
     */
    public int totalSize() {
        return queues.values().stream().mapToInt(BlockingQueue::size).sum();
    }

    private BlockingQueue<Map<String, Object>> queueFor(String indexName) {
        return queues.computeIfAbsent(indexName, k -> new LinkedBlockingQueue<>(maxSizePerIndex));
    }
}
