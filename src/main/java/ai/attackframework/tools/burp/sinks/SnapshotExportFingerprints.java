package ai.attackframework.tools.burp.sinks;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;

/**
 * Stable in-memory item keys for sitemap/findings periodic export deduplication.
 *
 * <p>Keys are never written to OpenSearch documents.</p>
 */
final class SnapshotExportFingerprints {

    private SnapshotExportFingerprints() {}

    static String sitemapItemKey(HttpRequest request) {
        if (request == null) {
            return "";
        }
        String url = RequestResponseDocBuilder.safeRequestUrl(request, "Sitemap");
        if (url == null) {
            url = "";
        }
        String method = request.method() == null ? "" : request.method();
        return method + " " + url;
    }

    static String findingItemKey(AuditIssue issue) {
        if (issue == null) {
            return "";
        }
        int typeId = 0;
        try {
            AuditIssueDefinition definition = issue.definition();
            if (definition != null) {
                typeId = definition.typeIndex();
            }
        } catch (RuntimeException ignored) {
            // Burp lifecycle races can transiently reject definition access.
        }
        return typeId
                + "|"
                + nullToEmpty(issue.name())
                + "|"
                + nullToEmpty(issue.baseUrl())
                + "|"
                + detailFingerprint(issue);
    }

    /**
     * Stable short fingerprint for {@link AuditIssue#detail()} so distinct issues that share
     * type/name/base URL are not collapsed during periodic deduplication.
     */
    private static String detailFingerprint(AuditIssue issue) {
        try {
            String detail = issue.detail();
            if (detail == null || detail.isBlank()) {
                return "";
            }
            return Integer.toHexString(detail.hashCode());
        } catch (RuntimeException ignored) {
            // Burp lifecycle races can transiently reject detail access.
            return "";
        }
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
