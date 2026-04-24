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
 *
 * <p>Each queued document is wrapped with its enqueue timestamp so callers can observe
 * the age of the oldest retry-pending document per index.</p>
 */
public final class RetryQueue {

    /** A document waiting to be retried, tagged with the time it was enqueued. */
    record QueuedDoc(Map<String, Object> document, long enqueuedAtMs) {}

    private final int maxSizePerIndex;
    private final ConcurrentHashMap<String, BlockingQueue<QueuedDoc>> queues = new ConcurrentHashMap<>();

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
        BlockingQueue<QueuedDoc> q = queueFor(indexName);
        return q.offer(new QueuedDoc(document, System.currentTimeMillis()));
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
        BlockingQueue<QueuedDoc> q = queueFor(indexName);
        long now = System.currentTimeMillis();
        int added = 0;
        for (Map<String, Object> doc : documents) {
            if (!q.offer(new QueuedDoc(doc, now))) {
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
        BlockingQueue<QueuedDoc> q = queues.get(indexName);
        if (q == null) {
            return List.of();
        }
        List<QueuedDoc> wrapped = new ArrayList<>(Math.min(maxSize, q.size()));
        q.drainTo(wrapped, maxSize);
        List<Map<String, Object>> batch = new ArrayList<>(wrapped.size());
        for (QueuedDoc qd : wrapped) {
            batch.add(qd.document());
        }
        return batch;
    }

    /**
     * Returns the current number of documents queued for the given index.
     */
    public int size(String indexName) {
        BlockingQueue<QueuedDoc> q = queues.get(indexName);
        return q == null ? 0 : q.size();
    }

    /**
     * Returns the enqueue timestamp (epoch ms) of the oldest queued document for the given index,
     * or {@code -1} when the queue is empty or absent.
     *
     * <p>Uses a non-blocking {@link BlockingQueue#peek()} so reads are cheap and safe from any
     * thread; the returned value is a snapshot and may change immediately after reading.</p>
     */
    public long oldestEnqueuedAtMs(String indexName) {
        BlockingQueue<QueuedDoc> q = queues.get(indexName);
        if (q == null) {
            return -1L;
        }
        QueuedDoc head = q.peek();
        return head == null ? -1L : head.enqueuedAtMs();
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

    /**
     * Clears all queued retry documents across all indexes.
     */
    public void clearAll() {
        queues.values().forEach(BlockingQueue::clear);
    }

    private BlockingQueue<QueuedDoc> queueFor(String indexName) {
        return queues.computeIfAbsent(indexName, k -> new LinkedBlockingQueue<>(maxSizePerIndex));
    }
}
