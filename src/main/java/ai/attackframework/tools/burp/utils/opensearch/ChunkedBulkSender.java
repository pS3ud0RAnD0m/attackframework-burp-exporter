package ai.attackframework.tools.burp.utils.opensearch;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import ai.attackframework.tools.burp.sinks.BulkPayloadEstimator;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.ExportFieldFilter;

/**
 * Sends traffic documents to OpenSearch using a chunked POST to the standard Bulk API.
 *
 * <p>Drains from a queue and writes NDJSON (action line + doc line per document) directly into
 * the request body stream. Avoids building a full batch list and full {@code BulkRequest} in
 * memory. Uses only the production Bulk API ({@code POST /&lt;index&gt;/_bulk}); not the
 * experimental Streaming Bulk API. Thread-safe for concurrent calls; each call performs one
 * bulk request. Used only by the traffic export path.</p>
 *
 * @see <a href="https://docs.opensearch.org/latest/api-reference/document-apis/bulk/">Bulk API</a>
 */
public final class ChunkedBulkSender {

    private static final String INDEX_ACTION_LINE = "{\"index\":{}}\n";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final CloseableHttpClient HTTP_CLIENT = HttpClients.createDefault();

    private ChunkedBulkSender() {}

    /**
     * Result of one chunked bulk request: success count and total documents sent.
     */
    public static final class Result {
        /** Number of documents that were successfully indexed. */
        public final int successCount;
        /** Total number of documents sent in this bulk request. */
        public final int attemptedCount;

        public Result(int successCount, int attemptedCount) {
            this.successCount = successCount;
            this.attemptedCount = attemptedCount;
        }
        public boolean isFullSuccess() { return attemptedCount > 0 && successCount == attemptedCount; }
    }

    /**
     * Performs one chunked bulk index request: drains from the queue (respecting batch limits),
     * writes NDJSON to {@code POST &lt;baseUrl&gt;/&lt;indexName&gt;/_bulk}, parses the response.
     *
     * <p>Documents are filtered with {@link ExportFieldFilter#filterDocument} for the
     * {@code traffic} index before writing. Batch is limited by {@code maxBatch} doc count,
     * {@code maxBytes} estimated payload size, and {@code maxWaitMs} time. If no document
     * is available within the first {@code maxWaitMs}, returns a result with zero attempted
     * count (no request is sent).</p>
     *
     * @param baseUrl    OpenSearch base URL (e.g. {@code http://opensearch.url:9200})
     * @param indexName  target index name (e.g. {@code attackframework-tool-burp-traffic})
     * @param queue      source of documents; each element is a {@code Map} to index
     * @param maxBatch   maximum documents per bulk request
     * @param maxBytes   maximum estimated payload bytes per bulk request
     * @param maxWaitMs  maximum time to wait for the first document before sending
     * @return result with success and attempted counts; never {@code null}
     */
    public static Result push(
            String baseUrl,
            String indexName,
            BlockingQueue<Map<String, Object>> queue,
            int maxBatch,
            long maxBytes,
            long maxWaitMs) {
        String bulkUrl = buildBulkUrl(baseUrl, indexName);
        HttpPost post = new HttpPost(URI.create(bulkUrl));
        long maxWaitNanos = maxWaitMs * 1_000_000L;
        AtomicInteger attemptedRef = new AtomicInteger(0);
        InputStream ndjsonStream = new NdjsonQueueInputStream(queue, maxBatch, maxBytes, maxWaitNanos, attemptedRef);
        post.setEntity(new InputStreamEntity(ndjsonStream, -1, ContentType.create("application/x-ndjson")));

        try (CloseableHttpResponse response = executeRequest(post)) {
            int status = response.getCode();
            String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            int attempted = attemptedRef.get();
            if (status < 200 || status >= 300) {
                Logger.logDebug("ChunkedBulkSender bulk request failed: " + status + " " + responseBody);
                return new Result(0, attempted);
            }
            return parseBulkResponse(responseBody, attempted);
        } catch (IOException | ParseException | RuntimeException e) {
            Logger.logDebug("ChunkedBulkSender push failed for " + indexName + ": " + e.getMessage());
            return new Result(0, attemptedRef.get());
        }
    }

    @SuppressWarnings("deprecation")
    private static CloseableHttpResponse executeRequest(HttpPost post) throws IOException {
        return HTTP_CLIENT.execute(post);
    }

    static String buildBulkUrl(String baseUrl, String indexName) {
        String base = baseUrl == null ? "" : baseUrl.trim();
        if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        return base + "/" + indexName + "/_bulk";
    }

    /** Package-private for tests. */
    static Result parseBulkResponse(String responseBody, int attemptedCount) {
        if (responseBody == null || responseBody.isBlank()) {
            return new Result(0, attemptedCount);
        }
        try {
            JsonNode root = JSON.readTree(responseBody);
            JsonNode items = root.get("items");
            if (items == null || !items.isArray()) {
                return new Result(0, attemptedCount);
            }
            ArrayNode arr = (ArrayNode) items;
            int successCount = 0;
            int maxLogged = 3;
            int logged = 0;
            for (int i = 0; i < arr.size(); i++) {
                JsonNode item = arr.get(i);
                JsonNode op = item.get("index");
                if (op == null) op = item.get("create");
                if (op == null) op = item.get("update");
                int status = (op != null && op.has("status")) ? op.get("status").asInt() : 0;
                if (status >= 200 && status < 300) {
                    successCount++;
                } else if (logged < maxLogged) {
                    JsonNode err = op != null ? op.get("error") : null;
                    String reason = err != null && err.has("reason") ? err.get("reason").asText() : "unknown";
                    Logger.logDebug("Bulk item error at " + i + ": " + reason);
                    logged++;
                }
            }
            if (arr.size() - successCount > maxLogged) {
                Logger.logDebug("Bulk index: " + (arr.size() - successCount - maxLogged) + " more item errors (total failed: " + (arr.size() - successCount) + ")");
            }
            return new Result(successCount, attemptedCount);
        } catch (Exception e) {
            Logger.logDebug("ChunkedBulkSender parse response failed: " + e.getMessage());
            return new Result(0, attemptedCount);
        }
    }

    /**
     * InputStream that produces NDJSON by draining from a queue one document at a time.
     * Used as the body of a chunked bulk request. Only one doc's bytes are held in memory
     * at a time. Stops when batch count, size, or time limit is reached.
     */
    private static final class NdjsonQueueInputStream extends InputStream {
        private final BlockingQueue<Map<String, Object>> queue;
        private final int maxBatch;
        private final long maxBytes;
        private final long maxWaitNanos;
        private final AtomicInteger attemptedRef;

        private byte[] buffer = new byte[0];
        private int pos;
        private boolean finished;
        private long batchStartNanos = System.nanoTime();
        private long runningBytes;

        NdjsonQueueInputStream(BlockingQueue<Map<String, Object>> queue, int maxBatch, long maxBytes,
                long maxWaitNanos, AtomicInteger attemptedRef) {
            this.queue = queue;
            this.maxBatch = maxBatch;
            this.maxBytes = maxBytes;
            this.maxWaitNanos = maxWaitNanos;
            this.attemptedRef = attemptedRef;
        }

        @Override
        public int read() throws IOException {
            if (finished) return -1;
            if (pos < buffer.length) return buffer[pos++] & 0xFF;
            if (!fillBuffer()) {
                finished = true;
                return -1;
            }
            return pos < buffer.length ? buffer[pos++] & 0xFF : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (finished) return -1;
            if (pos < buffer.length) {
                int toCopy = Math.min(len, buffer.length - pos);
                System.arraycopy(buffer, pos, b, off, toCopy);
                pos += toCopy;
                return toCopy;
            }
            if (!fillBuffer()) {
                finished = true;
                return -1;
            }
            int toCopy = Math.min(len, buffer.length - pos);
            System.arraycopy(buffer, pos, b, off, toCopy);
            pos += toCopy;
            return toCopy;
        }

        /** Fetches one document from the queue, serializes to NDJSON, and sets buffer. */
        private boolean fillBuffer() throws IOException {
            if (attemptedRef.get() >= maxBatch) return false;
            if ((System.nanoTime() - batchStartNanos) >= maxWaitNanos) return false;
            Map<String, Object> doc;
            try {
                if (attemptedRef.get() == 0) {
                    doc = queue.poll(maxWaitNanos / 1_000_000, TimeUnit.MILLISECONDS);
                } else {
                    doc = queue.poll();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
            if (doc == null) return false;
            Map<String, Object> filtered = ExportFieldFilter.filterDocument(doc, "traffic");
            long docBytes = BulkPayloadEstimator.estimateBytes(filtered);
            if (attemptedRef.get() > 0 && runningBytes + docBytes > maxBytes) {
                queue.offer(doc);
                return false;
            }
            ByteArrayOutputStream chunk = new ByteArrayOutputStream();
            chunk.write(INDEX_ACTION_LINE.getBytes(StandardCharsets.UTF_8));
            JSON.writeValue(chunk, filtered);
            chunk.write('\n');
            buffer = chunk.toByteArray();
            pos = 0;
            attemptedRef.incrementAndGet();
            runningBytes += docBytes;
            return true;
        }
    }
}
