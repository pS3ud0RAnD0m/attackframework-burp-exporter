package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.config.ConfigState;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

class FindingsSeverityFilterTest {

    @Test
    void matches_informationalToken_toInformationEnum() {
        assertThat(FindingsSeverityFilter.matches(
                AuditIssueSeverity.INFORMATION,
                Set.of("informational")))
                .isTrue();
    }

    @Test
    void matches_directEnumName_whenTokenMatchesMontoyaName() {
        assertThat(FindingsSeverityFilter.matches(
                AuditIssueSeverity.HIGH,
                Set.of("high")))
                .isTrue();
    }

    @Test
    void doesNotMatch_informationEnum_whenOnlyHighSelected() {
        assertThat(FindingsSeverityFilter.matches(
                AuditIssueSeverity.INFORMATION,
                Set.of("high")))
                .isFalse();
    }

    @Test
    void doesNotMatch_nullSeverity() {
        assertThat(FindingsSeverityFilter.matches(null, Set.of("high", "informational")))
                .isFalse();
    }

    @Test
    void isOperatorExcluded_forNullAndFalsePositive() {
        assertThat(FindingsSeverityFilter.isOperatorExcluded(null)).isTrue();
        assertThat(FindingsSeverityFilter.isOperatorExcluded(AuditIssueSeverity.FALSE_POSITIVE)).isTrue();
        assertThat(FindingsSeverityFilter.isOperatorExcluded(AuditIssueSeverity.HIGH)).isFalse();
    }

    @Test
    void shouldExport_neverExportsOperatorExcluded() {
        Set<String> allDefaults = Set.copyOf(ConfigState.DEFAULT_FINDINGS_SEVERITIES);
        assertThat(FindingsSeverityFilter.shouldExport(null, true, allDefaults)).isFalse();
        assertThat(FindingsSeverityFilter.shouldExport(
                AuditIssueSeverity.FALSE_POSITIVE, true, allDefaults))
                .isFalse();
        assertThat(FindingsSeverityFilter.shouldExport(
                AuditIssueSeverity.FALSE_POSITIVE, false, allDefaults))
                .isFalse();
    }

    @Test
    void shouldExport_exportsInformationWithDefaultConfig() {
        assertThat(FindingsSeverityFilter.shouldExport(
                AuditIssueSeverity.INFORMATION,
                true,
                Set.copyOf(ConfigState.DEFAULT_FINDINGS_SEVERITIES)))
                .isTrue();
    }

    @Test
    void countsTowardSkippedSeverity_ignoresOperatorExcluded() {
        Set<String> allDefaults = Set.copyOf(ConfigState.DEFAULT_FINDINGS_SEVERITIES);
        assertThat(FindingsSeverityFilter.countsTowardSkippedSeverity(
                null, true, allDefaults))
                .isFalse();
        assertThat(FindingsSeverityFilter.countsTowardSkippedSeverity(
                AuditIssueSeverity.FALSE_POSITIVE, true, allDefaults))
                .isFalse();
    }

    @Test
    void countsTowardSkippedSeverity_whenSeverityNotSelected() {
        assertThat(FindingsSeverityFilter.countsTowardSkippedSeverity(
                AuditIssueSeverity.INFORMATION,
                true,
                Set.of("high")))
                .isTrue();
    }

    @Test
    void falsePositiveTokenDoesNotMatchEvenWhenExplicitlyInConfig() {
        assertThat(FindingsSeverityFilter.matches(
                AuditIssueSeverity.FALSE_POSITIVE,
                Set.of("false_positive")))
                .isFalse();
    }

    @Test
    void criticalTokenDoesNotMatchAnyMontoyaSeverity() {
        for (AuditIssueSeverity severity : AuditIssueSeverity.values()) {
            assertThat(FindingsSeverityFilter.matches(severity, Set.of("critical")))
                    .isFalse();
        }
    }

    @Test
    void configTokenFor_mapsInformationToInformational() {
        assertThat(FindingsSeverityFilter.configTokenFor(AuditIssueSeverity.INFORMATION))
                .isEqualTo("informational");
        assertThat(FindingsSeverityFilter.configTokenFor(AuditIssueSeverity.FALSE_POSITIVE))
                .isNull();
    }
}
