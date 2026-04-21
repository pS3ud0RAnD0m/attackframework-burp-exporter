package ai.attackframework.tools.burp.sinks;

/**
 * Shared capture-policy helpers for startup Repeater-history observations.
 *
 * <p>This collaborator centralizes the logic that decides whether a startup editor callback maps to
 * a logical historic Repeater tab, what dedupe key that observation should use, and how metadata
 * should be described in trace logs.</p>
 */
final class RepeaterHistoryCapturePolicy {

    private RepeaterHistoryCapturePolicy() {}

    /**
     * Builds the capture decision for one observed Repeater-history binding.
     *
     * <p>Startup captures prefer logical slot keys so distinct tabs with identical traffic still
     * export separately. Startup callbacks that expose no slot, tab, or group metadata are treated
     * as anonymous editor noise and ignored.</p>
     */
    static CaptureDecision decide(
            String fingerprint,
            RepeaterHistoryIndexReporter.RepeaterTabMetadata metadata,
            boolean startupCaptureWindowOpen) {
        String startupSlotKey = startupCaptureWindowOpen ? startupSlotKey(metadata) : null;
        String captureKey = startupSlotKey == null ? fingerprint : "slot:" + startupSlotKey;
        boolean ignoreAnonymousStartupBinding = startupCaptureWindowOpen
                && (metadata == null
                || (metadata.slotIdentityKey() == null
                && metadata.tabName() == null
                && metadata.groupName() == null));
        return new CaptureDecision(captureKey, startupSlotKey, ignoreAnonymousStartupBinding);
    }

    static String startupSlotKey(RepeaterHistoryIndexReporter.RepeaterTabMetadata metadata) {
        if (metadata == null || metadata.slotIdentityKey() == null) {
            return null;
        }
        return metadata.slotIdentityKey();
    }

    static String describeMetadata(RepeaterHistoryIndexReporter.RepeaterTabMetadata metadata) {
        if (metadata == null) {
            return "tab=<null> group=<null> slot=<null> root=<null>";
        }
        return "tab=" + safeLogValue(metadata.tabName())
                + " group=" + safeLogValue(metadata.groupName())
                + " slot=" + safeLogValue(metadata.slotIdentityKey())
                + " root=" + safeLogValue(metadata.rootComponentClass());
    }

    static String safeLogValue(String value) {
        return value == null ? "<null>" : value;
    }

    /**
     * Capture-policy outcome for one observed Repeater-history binding.
     *
     * @param captureKey dedupe/export key for this observation
     * @param startupSlotKey logical startup slot key when available
     * @param ignoreAnonymousStartupBinding whether this startup-only binding should be suppressed
     */
    static record CaptureDecision(
            String captureKey,
            String startupSlotKey,
            boolean ignoreAnonymousStartupBinding) { }
}
