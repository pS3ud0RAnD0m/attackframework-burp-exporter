package ai.anomalousvectors.tools.burp.sinks;

/**
 * Shared capture-policy helpers for startup Repeater-tab observations.
 *
 * <p>This collaborator centralizes the logic that decides whether a startup editor callback maps to
 * a logical historic Repeater tab, what capture key that observation should use, and how metadata
 * should be described in trace logs.</p>
 */
final class RepeaterTabsCapturePolicy {

    private RepeaterTabsCapturePolicy() {}

    /**
     * Builds the capture decision for one observed Repeater-tab binding.
     *
     * <p>Startup captures prefer logical slot keys so distinct tabs with identical traffic still
     * export separately. Startup callbacks that expose no slot, tab, or group metadata are treated
     * as anonymous editor noise and ignored. Bindings whose inferred {@code tab_name} is an
     * auxiliary message-view label (Inspector, Notes, Explanations, Raw, …) are suppressed even
     * outside the startup capture window.</p>
     */
    static CaptureDecision decide(
            String fingerprint,
            RepeaterTabsIndexReporter.RepeaterTabMetadata metadata,
            boolean startupCaptureWindowOpen) {
        String startupSlotKey = startupCaptureWindowOpen ? startupSlotKey(metadata) : null;
        String captureKey = startupSlotKey == null ? fingerprint : "slot:" + startupSlotKey;
        boolean ignoreAnonymousStartupBinding = startupCaptureWindowOpen
                && (metadata == null
                || (metadata.slotIdentityKey() == null
                && metadata.tabName() == null
                && metadata.groupName() == null));
        boolean ignoreAuxiliaryTabNameBinding = metadata != null
                && RepeaterTabMetadataHeuristics.isAuxiliaryRepeaterTabLabel(metadata.tabName());
        return new CaptureDecision(
                captureKey,
                startupSlotKey,
                ignoreAnonymousStartupBinding,
                ignoreAuxiliaryTabNameBinding);
    }

    static String startupSlotKey(RepeaterTabsIndexReporter.RepeaterTabMetadata metadata) {
        if (metadata == null || metadata.slotIdentityKey() == null) {
            return null;
        }
        return metadata.slotIdentityKey();
    }

    static String describeMetadata(RepeaterTabsIndexReporter.RepeaterTabMetadata metadata) {
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
     * Capture-policy outcome for one observed Repeater-tab binding.
     *
     * @param captureKey capture key for this observation
     * @param startupSlotKey logical startup slot key when available
     * @param ignoreAnonymousStartupBinding whether this startup-only binding should be suppressed
     * @param ignoreAuxiliaryTabNameBinding whether the inferred tab name is a right-rail view label
     */
    static record CaptureDecision(
            String captureKey,
            String startupSlotKey,
            boolean ignoreAnonymousStartupBinding,
            boolean ignoreAuxiliaryTabNameBinding) { }
}
