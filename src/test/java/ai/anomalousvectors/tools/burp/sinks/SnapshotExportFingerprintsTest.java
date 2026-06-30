package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;

class SnapshotExportFingerprintsTest {

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
                + "34881c1f99c492197997d9d736bcedc95e0c3494e0d523b8e060b4a1360eeb63";
        assertThat(SnapshotExportFingerprints.findingItemKey(issue)).isEqualTo(expected);
    }

    @Test
    void sitemapEntryFingerprint_differsWhenRequestBodyDiffers() {
        HttpRequestResponse first = mockSitemapItem("GET", "https://example.com/a", "body-a");
        HttpRequestResponse second = mockSitemapItem("GET", "https://example.com/a", "body-b");

        assertThat(SnapshotExportFingerprints.sitemapEntryFingerprint(first))
                .isNotEqualTo(SnapshotExportFingerprints.sitemapEntryFingerprint(second));
    }

    @Test
    void sitemapEntryFingerprint_differsForSameMethodAndUrlOnly() {
        HttpRequestResponse first = mockSitemapItem("POST", "https://example.com/a", "alpha");
        HttpRequestResponse second = mockSitemapItem("POST", "https://example.com/a", "beta");

        assertThat(SnapshotExportFingerprints.sitemapEntryFingerprint(first))
                .isNotEqualTo(SnapshotExportFingerprints.sitemapEntryFingerprint(second));
    }

    @Test
    void sitemapEntryFingerprint_stableForIdenticalTraffic() {
        HttpRequestResponse first = mockSitemapItem("POST", "https://example.com/a", "same");
        HttpRequestResponse second = mockSitemapItem("POST", "https://example.com/a", "same");

        assertThat(SnapshotExportFingerprints.sitemapEntryFingerprint(first))
                .isEqualTo(SnapshotExportFingerprints.sitemapEntryFingerprint(second));
    }

    private static HttpRequestResponse mockSitemapItem(String method, String url, String body) {
        byte[] raw = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteArray requestBytes = mock(ByteArray.class);
        when(requestBytes.getBytes()).thenReturn(raw);
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn(method);
        when(request.url()).thenReturn(url);
        when(request.toByteArray()).thenReturn(requestBytes);

        HttpRequestResponse item = mock(HttpRequestResponse.class);
        when(item.request()).thenReturn(request);
        when(item.response()).thenReturn(null);
        when(item.annotations()).thenReturn(null);
        return item;
    }
}
