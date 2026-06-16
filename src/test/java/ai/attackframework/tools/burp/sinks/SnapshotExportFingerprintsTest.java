package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;

class SnapshotExportFingerprintsTest {

    @Test
    void sitemapItemKey_usesMethodAndUrl() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.com/a");
        when(request.method()).thenReturn("POST");

        assertThat(SnapshotExportFingerprints.sitemapItemKey(request))
                .isEqualTo("POST https://example.com/a");
    }

    @Test
    void findingItemKey_usesTypeIdNameAndBaseUrl() {
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        when(issue.definition()).thenReturn(definition);
        when(definition.typeIndex()).thenReturn(42);
        when(issue.name()).thenReturn("SQL injection");
        when(issue.baseUrl()).thenReturn("https://example.com/");

        assertThat(SnapshotExportFingerprints.findingItemKey(issue))
                .isEqualTo("42|SQL injection|https://example.com/|");
    }

    @Test
    void findingItemKey_includesDetailFingerprintWhenPresent() {
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        when(issue.definition()).thenReturn(definition);
        when(definition.typeIndex()).thenReturn(1);
        when(issue.name()).thenReturn("XSS");
        when(issue.baseUrl()).thenReturn("https://example.com/");
        when(issue.detail()).thenReturn("Reflected in param q");

        String expected = "1|XSS|https://example.com/|"
                + Integer.toHexString("Reflected in param q".hashCode());
        assertThat(SnapshotExportFingerprints.findingItemKey(issue)).isEqualTo(expected);
    }
}
