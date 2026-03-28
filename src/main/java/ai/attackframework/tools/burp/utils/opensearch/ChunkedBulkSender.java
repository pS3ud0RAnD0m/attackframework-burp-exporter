package ai.attackframework.tools.burp.utils.opensearch;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import ai.attackframework.tools.burp.sinks.BulkPayloadEstimator;
import ai.attackframework.tools.burp.sinks.FileExportService;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.ExportDocumentIdentity;
import ai.attackframework.tools.burp.utils.export.ExportLineCodec;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

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

    private static final ObjectMapper JSON = new ObjectMapper();

    private ChunkedBulkSender() {}

    /**
     * Result of one chunked bulk request: success count and total documents sent.
     */
    public static final class Result {
        /** Number of documents that were successfully indexed. */
        public final int successCount;
        /** Total number of documents sent in this bulk request. */
        public final int attemptedCount;
        /** Estimated payload bytes attempted in this bulk request. */
        public final long attemptedBytes;
        /** Estimated payload bytes for successful documents in this bulk request. */
        public final long successBytes;

        public Result(int successCount, int attemptedCount, long attemptedBytes, long successBytes) {
            this.successCount = successCount;
            this.attemptedCount = attemptedCount;
            this.attemptedBytes = attemptedBytes;
            this.successBytes = successBytes;
        }
        public boolean isFullSuccess() { return attemptedCount > 0 && successCount == attemptedCount; }
    }

    /**
     * Performs one chunked bulk index request: drains from the queue (respecting batch limits),
     * writes NDJSON to {@code POST &lt;baseUrl&gt;/&lt;indexName&gt;/_bulk}, parses the response.
     *
     * <p>Documents are prepared with the shared export-ID path before writing. Batch is limited by
     * {@code maxBatch} doc count,
     * {@code maxBytes} estimated payload size, and {@code maxWaitMs} time. If no document
     * is available within the first {@code maxWaitMs}, returns a result with zero attempted
     * count (no request is sent).</p>
     *
     * @param baseUrl    OpenSearch base URL (e.g. {@code https://opensearch.url:9200})
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
        Map<String, Object> firstDoc = pollFirstDoc(queue, maxWaitMs);
        if (firstDoc == null) {
            return new Result(0, 0, 0, 0);
        }
        String bulkUrl = buildBulkUrl(baseUrl, indexName);
        HttpPost post = new HttpPost(URI.create(bulkUrl));
        long maxWaitNanos = maxWaitMs * 1_000_000L;
        AtomicInteger attemptedRef = new AtomicInteger(0);
        AtomicLong attemptedBytesRef = new AtomicLong(0);
        InputStream ndjsonStream = new NdjsonQueueInputStream(
                indexName, queue, firstDoc, maxBatch, maxBytes, maxWaitNanos, attemptedRef, attemptedBytesRef);
        post.setEntity(new InputStreamEntity(ndjsonStream, -1, ContentType.create("application/x-ndjson")));
        addPreemptiveBasicAuthHeader(post);

        try (CloseableHttpResponse response = executeRequest(baseUrl, post)) {
            int status = response.getCode();
            String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            int attempted = attemptedRef.get();
            long attemptedBytes = attemptedBytesRef.get();
            if (status < 200 || status >= 300) {
                Logger.logDebug("ChunkedBulkSender bulk request failed: " + status + " " + responseBody);
                return new Result(0, attempted, attemptedBytes, 0);
            }
            Result parsed = parseBulkResponse(responseBody, attempted);
            long successBytes = parsed.successCount > 0 && attempted > 0
                    ? Math.round((double) attemptedBytes * parsed.successCount / attempted)
                    : 0;
            return new Result(parsed.successCount, parsed.attemptedCount, attemptedBytes, successBytes);
        } catch (IOException | ParseException | RuntimeException e) {
            long attemptedBytes = attemptedBytesRef.get();
            Logger.logDebug("ChunkedBulkSender push failed for " + indexName + ": " + e.getMessage());
            return new Result(0, attemptedRef.get(), attemptedBytes, 0);
        }
    }

    @SuppressWarnings("deprecation")
    private static CloseableHttpResponse executeRequest(String baseUrl, HttpPost post) throws IOException {
        CloseableHttpClient client = OpenSearchConnector.getClassicHttpClient(
                baseUrl, RuntimeConfig.openSearchUser(), RuntimeConfig.openSearchPassword());
        return client.execute(post);
    }

    /**
     * Adds a preemptive Basic Auth header when credentials are configured.
     *
     * <p>Chunked NDJSON entities are not repeatable. If authentication waits for a 401 challenge,
     * some clients cannot transparently replay the same request body. Sending Authorization on the
     * first request avoids repeated 401 loops on the live traffic bulk path.</p>
     */
    static void addPreemptiveBasicAuthHeader(HttpPost post) {
        String username = RuntimeConfig.openSearchUser();
        String password = RuntimeConfig.openSearchPassword();
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            return;
        }
        String token = Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        post.setHeader("Authorization", "Basic " + token);
    }

    private static Map<String, Object> pollFirstDoc(BlockingQueue<Map<String, Object>> queue, long maxWaitMs) {
        try {
            return queue.poll(maxWaitMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    static String buildBulkUrl(String baseUrl, String indexName) {
        String base = baseUrl == null ? "" : baseUrl.trim();
        if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        return base + "/" + indexName + "/_bulk";
    }

    /** Package-private for tests. */
    static Result parseBulkResponse(String responseBody, int attemptedCount) {
        if (responseBody == null || responseBody.isBlank()) {
            return new Result(0, attemptedCount, 0, 0);
        }
        try {
            JsonNode root = JSON.readTree(responseBody);
            JsonNode items = root.get("items");
            if (items == null || !items.isArray()) {
                return new Result(0, attemptedCount, 0, 0);
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
            return new Result(successCount, attemptedCount, 0, 0);
        } catch (IOException | RuntimeException e) {
            Logger.logDebug("ChunkedBulkSender parse response failed: " + e.getMessage());
            return new Result(0, attemptedCount, 0, 0);
        }
    }

    /**
     * InputStream that produces NDJSON by draining from a queue one document at a time.
     * Used as the body of a chunked bulk request. Only one doc's bytes are held in memory
     * at a time. Stops when batch count, size, or time limit is reached.
     */
    private static final class NdjsonQueueInputStream extends InputStream {
        private final String indexName;
        private final BlockingQueue<Map<String, Object>> queue;
        private Map<String, Object> firstDoc;
        private final int maxBatch;
        private final long maxBytes;
        private final long maxWaitNanos;
        private final AtomicInteger attemptedRef;
        private final AtomicLong attemptedBytesRef;

        private byte[] buffer = new byte[0];
        private int pos;
        private boolean finished;
        private final long batchStartNanos = System.nanoTime();
        private long runningBytes;

        NdjsonQueueInputStream(
                String indexName,
                BlockingQueue<Map<String, Object>> queue,
                Map<String, Object> firstDoc,
                int maxBatch,
                long maxBytes,
                long maxWaitNanos, AtomicInteger attemptedRef, AtomicLong attemptedBytesRef) {
            this.indexName = indexName;
            this.queue = queue;
            this.firstDoc = firstDoc;
            this.maxBatch = maxBatch;
            this.maxBytes = maxBytes;
            this.maxWaitNanos = maxWaitNanos;
            this.attemptedRef = attemptedRef;
            this.attemptedBytesRef = attemptedBytesRef;
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
            Map<String, Object> doc = firstDoc;
            if (doc != null) {
                firstDoc = null;
            } else {
                doc = queue.poll();
            }
            if (doc == null) return false;
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, doc);
            long docBytes = BulkPayloadEstimator.estimateBytes(prepared.document());
            if (attemptedRef.get() > 0 && runningBytes + docBytes > maxBytes) {
                queue.offer(doc);
                return false;
            }
            ByteArrayOutputStream chunk = new ByteArrayOutputStream();
            FileExportService.emit(prepared);
            ExportLineCodec.writeBulkNdjson(chunk, prepared);
            buffer = chunk.toByteArray();
            pos = 0;
            attemptedRef.incrementAndGet();
            runningBytes += docBytes;
            attemptedBytesRef.addAndGet(docBytes);
            return true;
        }
    }
}
