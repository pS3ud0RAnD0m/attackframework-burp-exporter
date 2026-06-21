package ai.attackframework.tools.burp.sinks;

import java.util.Map;
import java.util.Set;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Maps configured findings severity tokens to Montoya {@link AuditIssueSeverity} values.
 *
 * <p>Config and UI use lowercase tokens such as {@code informational}; Montoya enum names differ
 * (for example {@code INFORMATION}). The {@code critical} token is retained for config compatibility
 * but has no Montoya enum counterpart in montoya-api 2026.4.</p>
 *
 * <p>{@link AuditIssueSeverity#FALSE_POSITIVE} and {@code null} severities are never exported and
 * do not count toward backlog {@code skipped_severity}.</p>
 */
final class FindingsSeverityFilter {

    private static final Map<String, AuditIssueSeverity> CONFIG_TOKEN_TO_SEVERITY = Map.of(
            "high", AuditIssueSeverity.HIGH,
            "medium", AuditIssueSeverity.MEDIUM,
            "low", AuditIssueSeverity.LOW,
            "informational", AuditIssueSeverity.INFORMATION);

    private FindingsSeverityFilter() {}

    /**
     * Returns whether the issue severity is omitted from export and severity-filter metrics.
     *
     * @param severity Montoya issue severity
     * @return {@code true} for {@code null} or {@link AuditIssueSeverity#FALSE_POSITIVE}
     */
    static boolean isOperatorExcluded(AuditIssueSeverity severity) {
        return severity == null || severity == AuditIssueSeverity.FALSE_POSITIVE;
    }

    /**
     * Returns whether {@code severity} should be exported for the selected {@code configTokens}.
     *
     * @param severity Montoya issue severity
     * @param filterBySeverity when {@code false}, all non-excluded severities export
     * @param configTokens normalized lowercase tokens from config; ignored when not filtering
     * @return {@code true} when the issue should be exported
     */
    static boolean shouldExport(
            AuditIssueSeverity severity,
            boolean filterBySeverity,
            Set<String> configTokens) {
        if (isOperatorExcluded(severity)) {
            return false;
        }
        if (!filterBySeverity) {
            return true;
        }
        return matches(severity, configTokens);
    }

    /**
     * Returns whether a filtered-out issue should increment backlog {@code skipped_severity}.
     *
     * @param severity Montoya issue severity
     * @param filterBySeverity when {@code false}, nothing counts as skipped
     * @param configTokens normalized lowercase tokens from config
     * @return {@code true} when the issue was skipped by operator severity selection
     */
    static boolean countsTowardSkippedSeverity(
            AuditIssueSeverity severity,
            boolean filterBySeverity,
            Set<String> configTokens) {
        if (!filterBySeverity || isOperatorExcluded(severity)) {
            return false;
        }
        return !matches(severity, configTokens);
    }

    /**
     * Returns whether {@code severity} matches any selected {@code configTokens}.
     *
     * @param severity Montoya issue severity; {@code null} never matches
     * @param configTokens normalized lowercase tokens from config; must be non-empty
     * @return {@code true} when the severity is selected for export
     */
    static boolean matches(AuditIssueSeverity severity, Set<String> configTokens) {
        if (isOperatorExcluded(severity) || configTokens == null || configTokens.isEmpty()) {
            return false;
        }
        for (String token : configTokens) {
            if ("false_positive".equals(token)) {
                continue;
            }
            AuditIssueSeverity mapped = CONFIG_TOKEN_TO_SEVERITY.get(token);
            if (mapped != null && mapped == severity) {
                return true;
            }
            if (severity.name().equalsIgnoreCase(token)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the normalized config token for a Montoya severity, when one exists.
     *
     * @param severity Montoya severity
     * @return lowercase config token, or {@code null} when unmapped or operator-excluded
     */
    static String configTokenFor(AuditIssueSeverity severity) {
        if (isOperatorExcluded(severity)) {
            return null;
        }
        return switch (severity) {
            case HIGH -> "high";
            case MEDIUM -> "medium";
            case LOW -> "low";
            case INFORMATION -> "informational";
            case FALSE_POSITIVE -> null;
        };
    }
}
