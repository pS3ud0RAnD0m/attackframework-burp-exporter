package ai.attackframework.tools.burp.sinks;

/**
 * Result of an immediate exporter stats snapshot push.
 *
 * <p>Distinguishes intentional skips (disabled sub-option or no sink) from transport failures so
 * Stop and unload paths can log accurately.</p>
 *
 * @param kind outcome category
 * @param detail optional human-readable skip or failure detail; {@code null} on success
 */
public record ExporterStatsPushOutcome(Kind kind, String detail) {

    /** Outcome category for exporter stats push attempts. */
    public enum Kind {
        /** Exporter source or stats sub-option disabled. */
        SKIPPED_DISABLED,
        /** No file or OpenSearch sink enabled. */
        SKIPPED_NO_SINK,
        /** Document written to the configured sink. */
        SUCCESS,
        /** Push was attempted but failed. */
        FAILED
    }

    /**
     * Returns an outcome when exporter stats are disabled or the exporter source is off.
     *
     * @return skip outcome
     */
    public static ExporterStatsPushOutcome skippedDisabled() {
        return new ExporterStatsPushOutcome(Kind.SKIPPED_DISABLED, "exporter stats disabled");
    }

    /**
     * Returns an outcome when no sink is configured.
     *
     * @return skip outcome
     */
    public static ExporterStatsPushOutcome skippedNoSink() {
        return new ExporterStatsPushOutcome(Kind.SKIPPED_NO_SINK, "no sink enabled");
    }

    /**
     * Returns a successful push outcome.
     *
     * @return success outcome
     */
    public static ExporterStatsPushOutcome success() {
        return new ExporterStatsPushOutcome(Kind.SUCCESS, null);
    }

    /**
     * Returns a failed push outcome.
     *
     * @param reason failure detail; blank becomes {@code "unknown"}
     * @return failed outcome
     */
    public static ExporterStatsPushOutcome failed(String reason) {
        String normalized = reason == null || reason.isBlank() ? "unknown" : reason;
        return new ExporterStatsPushOutcome(Kind.FAILED, normalized);
    }

    /**
     * Returns whether the snapshot was written successfully.
     *
     * @return {@code true} only for {@link Kind#SUCCESS}
     */
    public boolean succeeded() {
        return kind == Kind.SUCCESS;
    }

    /**
     * Returns whether a push was attempted (success or failure).
     *
     * @return {@code true} when not a skip outcome
     */
    public boolean attempted() {
        return kind == Kind.SUCCESS || kind == Kind.FAILED;
    }
}
