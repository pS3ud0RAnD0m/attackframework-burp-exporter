package ai.attackframework.tools.burp.utils.opensearch;

import java.util.Locale;
import java.util.Set;

/**
 * Classifies a per-item OpenSearch bulk error as either permanently rejected or transient/retryable.
 *
 * <p>Permanently rejected errors indicate the document will never succeed as-is - typically
 * mapping or schema violations such as the Lucene immense-term cap, exceeded nested-object
 * limits, or strict-mapping rejections. The retry coordinator drops these after one attempt
 * (the "poison-pill" short-circuit) so the retry queue cannot loop on them.</p>
 *
 * <p>Transient errors cover cluster backpressure, temporary shard unavailability, timeouts,
 * and the default "unknown" case. The retry coordinator re-queues these so they can succeed
 * once the cluster recovers.</p>
 */
public enum BulkErrorClassification {
    PERMANENT,
    TRANSIENT;

    /**
     * OpenSearch/Elasticsearch error {@code type} strings that indicate a document-level,
     * non-recoverable failure. Matched case-insensitively.
     */
    private static final Set<String> PERMANENT_TYPES = Set.of(
            "illegal_argument_exception",
            "mapper_parsing_exception",
            "document_parsing_exception",
            "strict_dynamic_mapping_exception",
            "mapper_exception",
            "validation_exception",
            "parse_exception",
            "query_shard_exception");

    /**
     * Classifies a bulk item error based on its OpenSearch-supplied {@code type}.
     *
     * <p>Unknown or null types classify as {@link #TRANSIENT} deliberately: retrying an
     * unclassified failure is safer than dropping it. Add a type to {@link #PERMANENT_TYPES}
     * only when it represents a true document-level reject.</p>
     *
     * @param type the OpenSearch error type (e.g. {@code "mapper_parsing_exception"})
     * @return {@link #PERMANENT} when the type is known-permanent, otherwise {@link #TRANSIENT}
     */
    public static BulkErrorClassification of(String type) {
        if (type == null || type.isBlank()) {
            return TRANSIENT;
        }
        return PERMANENT_TYPES.contains(type.toLowerCase(Locale.ROOT)) ? PERMANENT : TRANSIENT;
    }
}
