package ai.attackframework.tools.burp.sinks;

/**
 * Shared label vocabulary for Repeater trace logging.
 *
 * <p>Repeater History and live Repeater export both rely on best-effort metadata inference. These
 * constants keep trace logs and user-facing docs aligned so operators can interpret the same
 * {@code metadataSource} terms everywhere without reverse-engineering each code path.</p>
 */
final class RepeaterMetadataTraceLabels {

    static final String STARTUP_SLOT = "startup_slot";
    static final String STARTUP_FINGERPRINT = "startup_fingerprint";
    static final String REQUEST_IDENTITY = "request_identity";
    static final String REQUEST_HASH = "request_hash";
    static final String EXCHANGE_HASH = "exchange_hash";
    static final String UI_FALLBACK = "ui_fallback";
    static final String REQUEST_STAGE_REUSE = "request_stage_reuse";
    static final String AMBIGUOUS_NULL = "ambiguous_null";
    static final String NONE = "none";

    private RepeaterMetadataTraceLabels() {}

    static String safeValue(String value) {
        return value == null ? "<null>" : value;
    }

    static String describeLiveMetadata(RepeaterMetadataFields.Metadata metadata) {
        RepeaterMetadataFields.Metadata value =
                metadata == null ? RepeaterMetadataFields.Metadata.empty() : metadata;
        return "tab=" + safeValue(value.tabName())
                + " group=" + safeValue(value.groupName());
    }

    static String historyMetadataSource(String captureKey) {
        return captureKey != null && captureKey.startsWith("slot:")
                ? STARTUP_SLOT
                : STARTUP_FINGERPRINT;
    }

    static String startupSessionId(int generation, int sessionSequence) {
        return "g" + generation + "-s" + sessionSequence;
    }
}
