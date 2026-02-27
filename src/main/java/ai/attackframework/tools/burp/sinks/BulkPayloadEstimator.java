package ai.attackframework.tools.burp.sinks;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Estimates approximate JSON payload size for bulk index requests.
 * Used to flush batches by payload size (e.g. 5 MB) in addition to doc count.
 */
public final class BulkPayloadEstimator {

    private BulkPayloadEstimator() {}

    /**
     * Estimates the approximate byte size of a document when serialized as JSON.
     * Counts key names, string values (UTF-8 length), and rough size for numbers/booleans/null;
     * recurses into nested maps and lists. Underestimates actual bulk JSON (no commas, braces
     * overhead) but is sufficient to cap batch payload size.
     *
     * @param doc document to estimate (can be null)
     * @return estimated size in bytes, or 0 if doc is null
     */
    public static long estimateBytes(Map<String, Object> doc) {
        if (doc == null) {
            return 0;
        }
        return estimateValue(doc);
    }

    private static long estimateValue(Object value) {
        if (value == null) {
            return 4; // "null"
        }
        if (value instanceof String s) {
            return s.getBytes(StandardCharsets.UTF_8).length + 2; // quotes
        }
        if (value instanceof Number) {
            return 20;
        }
        if (value instanceof Boolean) {
            return 5;
        }
        if (value instanceof Map<?, ?> map) {
            long sum = 2; // {}
            for (Map.Entry<?, ?> e : map.entrySet()) {
                Object k = e.getKey();
                Object v = e.getValue();
                sum += 3; // ": "
                if (k != null) {
                    sum += k.toString().getBytes(StandardCharsets.UTF_8).length + 2; // key as quoted
                }
                sum += estimateValue(v);
            }
            return sum;
        }
        if (value instanceof List<?> list) {
            long sum = 2; // []
            for (Object v : list) {
                sum += estimateValue(v);
            }
            return sum;
        }
        // byte[], or other: treat as string representation
        return value.toString().getBytes(StandardCharsets.UTF_8).length + 2;
    }
}
