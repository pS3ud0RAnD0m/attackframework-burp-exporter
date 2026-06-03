package ai.attackframework.tools.burp.ui.text;

import java.util.Map;

/**
 * Shared UI text for generated field checkboxes in the Config "Index Fields" section.
 */
public final class ExportFieldTooltips {

    private static final Map<String, String> SITEMAP_DISPLAY_NAMES = Map.of();
    private ExportFieldTooltips() {}

    /**
     * Checkbox/label text for a leaf under a top-level section (e.g. {@code comment} under Burp).
     * Tooltips still use the full dotted {@code fieldKey}.
     */
    public static String checkboxLabelUnderSection(String sectionPath, String fieldKey) {
        String rawLabel;
        if (sectionPath == null || sectionPath.isBlank()) {
            rawLabel = fieldKey;
        } else {
            String prefix = sectionPath + ".";
            rawLabel = fieldKey != null && fieldKey.startsWith(prefix)
                    ? fieldKey.substring(prefix.length())
                    : fieldKey;
        }
        return displayLabel(rawLabel);
    }

    private static String displayLabel(String fieldKey) {
        if (fieldKey == null || fieldKey.isBlank()) {
            return "";
        }
        String label = fieldKey.replace('_', ' ');
        return Character.toUpperCase(label.charAt(0)) + label.substring(1);
    }

    public static String displayNameFor(String indexShortName, String fieldKey) {
        if (isMetaField(fieldKey)) {
            return fieldKey;
        }
        if (isBurpField(fieldKey) && "settings".equals(indexShortName)) {
            return fieldKey;
        }
        if (isExporterEventField(fieldKey)) {
            return fieldKey;
        }
        return switch (indexShortName) {
            case "exporter" -> exporterDisplayName(fieldKey);
            case "settings" -> settingsDisplayName(fieldKey);
            case "sitemap" -> sitemapDisplayName(fieldKey);
            case "findings" -> findingsDisplayName(fieldKey);
            case "traffic" -> trafficDisplayName(fieldKey);
            default -> fieldKey;
        };
    }

    public static String tooltipFor(String indexShortName, String fieldKey) {
        return withFieldPathPrefix(fieldKey, tooltipBodyFor(indexShortName, fieldKey));
    }

    private static String tooltipBodyFor(String indexShortName, String fieldKey) {
        if (isMetaField(fieldKey)) {
            return metaTooltip(fieldKey);
        }
        if (isBurpField(fieldKey) && "settings".equals(indexShortName)) {
            return burpTooltip(fieldKey);
        }
        if (isExporterEventField(fieldKey)) {
            return exporterEventTooltip(fieldKey);
        }
        return switch (indexShortName) {
            case "exporter" -> exporterTooltip(fieldKey);
            case "settings" -> settingsTooltip(fieldKey);
            case "sitemap" -> sitemapTooltip(fieldKey);
            case "findings" -> findingsTooltip(fieldKey);
            case "traffic" -> trafficTooltip(fieldKey);
            default -> genericLeafTooltip(fieldKey);
        };
    }

    private static String withFieldPathPrefix(String fieldKey, String tooltipHtml) {
        if (fieldKey == null || fieldKey.isBlank()) {
            return tooltipHtml;
        }
        String fieldLine = "<b>Field:</b> " + Tooltips.escapeHtml(fieldKey);
        if (tooltipHtml == null || tooltipHtml.isBlank()) {
            return Tooltips.htmlRaw(fieldLine);
        }
        if (tooltipHtml.startsWith("<html>") && tooltipHtml.endsWith("</html>")) {
            String body = tooltipHtml.substring(6, tooltipHtml.length() - 7);
            return Tooltips.htmlRaw(fieldLine, body);
        }
        return Tooltips.htmlRaw(fieldLine, tooltipHtml);
    }

    static String genericLeafTooltip(String fieldKey) {
        return Tooltips.textWithSource(
                "Exported field mapped in OpenSearch as " + fieldKey + ".",
                "Included when this toggle is enabled in the Fields panel.");
    }

    private static boolean isMetaField(String fieldKey) {
        return fieldKey != null && fieldKey.startsWith("meta.");
    }

    private static String metaTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "meta.schema_version" -> Tooltips.textWithSource(
                    "Export schema version for this document.",
                    "Reporters write their cached schema constant into meta.schema_version before export.");
            case "meta.extension_version" -> Tooltips.textWithSource(
                    "Burp Exporter extension version that produced this document.",
                    "Reporters write the cached loaded extension version into meta.extension_version before export.");
            case "meta.indexed_at" -> Tooltips.textWithSource(
                    "Exporter indexing timestamp used as the canonical cross-index time field.",
                    "Each reporter writes Instant.now().toString() into meta.indexed_at before export.");
            case "meta.export_id" -> Tooltips.textWithSource(
                    "Stable content-derived export ID shared by files and OpenSearch.",
                    "ExportDocumentIdentity writes meta.export_id after field filtering; OpenSearch also uses it as _id.");
            default -> genericLeafTooltip(fieldKey);
        };
    }

    private static boolean isBurpField(String fieldKey) {
        return fieldKey != null && fieldKey.startsWith("burp.");
    }

    private static String burpTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "burp.project_id" -> Tooltips.textWithSource(
                    "Burp project identifier.",
                    "SettingsIndexReporter uses MontoyaApi.project().id(), falling back to BurpRuntimeMetadata.projectIdOrUnknown().");
            case "burp.version" -> Tooltips.textWithSource(
                    "Burp Suite version string.",
                    "SettingsIndexReporter uses MontoyaApi.burpSuite().version(), falling back to BurpRuntimeMetadata.burpVersion().");
            default -> genericLeafTooltip(fieldKey);
        };
    }

    private static boolean isExporterEventField(String fieldKey) {
        return fieldKey != null && fieldKey.startsWith("event.");
    }

    private static String exporterEventTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "event.data" -> Tooltips.textWithSource(
                    "Structured event payload when present.",
                    "ExporterIndexStatsReporter writes runtime metrics; ExporterIndexConfigReporter writes the normalized exporter configuration; log events do not populate this field.");
            case "event.level" -> Tooltips.textWithSource(
                    "Exporter event severity or verbosity level.",
                    "ExporterIndexLogForwarder forwards Logger levels; ExporterIndexStatsReporter and ExporterIndexConfigReporter write INFO.");
            case "event.source" -> Tooltips.textWithSource(
                    "Exporter event source label.",
                    "ExporterIndexLogForwarder, ExporterIndexStatsReporter, and ExporterIndexConfigReporter assign the component/source that produced the event.");
            case "event.summary" -> Tooltips.textWithSource(
                    "Concise human-readable event summary.",
                    "ExporterIndexLogForwarder stores the original log text; ExporterIndexStatsReporter and ExporterIndexConfigReporter build summary strings.");
            case "event.thread" -> Tooltips.textWithSource(
                    "Java producer thread name for the exporter event. Examples include AWT-EventQueue-0, attackframework-exporter-stats, attackframework-exporter-log-forwarder, and attackframework-settings-reporter.",
                    "Exporter reporters write Thread.currentThread().getName(); this is diagnostic runtime metadata, not the Burp tool, request thread, or OpenSearch thread.");
            case "event.type" -> Tooltips.textWithSource(
                    "Exporter event category.",
                    "ExporterIndexLogForwarder writes log_event; ExporterIndexStatsReporter writes stats_snapshot; ExporterIndexConfigReporter writes config_snapshot.");
            default -> genericLeafTooltip(fieldKey);
        };
    }

    private static String exporterDisplayName(String fieldKey) {
        return fieldKey;
    }

    private static String exporterTooltip(String fieldKey) {
        return fieldKey;
    }

    private static String settingsDisplayName(String fieldKey) {
        return fieldKey;
    }

    private static String settingsTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "user" -> Tooltips.textWithSource(
                    "Full user options JSON when User settings export is enabled.",
                    "SettingsIndexReporter uses MontoyaApi.burpSuite().exportUserOptionsAsJson().");
            case "project" -> Tooltips.textWithSource(
                    "Full project options JSON when Project settings export is enabled.",
                    "SettingsIndexReporter uses MontoyaApi.burpSuite().exportProjectOptionsAsJson().");
            default -> genericLeafTooltip(fieldKey);
        };
    }

    private static String sitemapDisplayName(String fieldKey) {
        if (fieldKey == null) {
            return null;
        }
        return SITEMAP_DISPLAY_NAMES.getOrDefault(fieldKey, fieldKey);
    }

    private static String sitemapTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "request.url" -> Tooltips.textWithSource(
                    "Full request URL for the sitemap item.",
                    "SitemapIndexReporter.buildSitemapDoc() uses RequestResponseDocBuilder.buildBestEffortUrl() from HttpRequest and HttpService.");
            case "request.port" -> Tooltips.textWithSource(
                    "Target port.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.httpService().port().");
            case "request.protocol.scheme" -> Tooltips.textWithSource(
                    "Request scheme: https or http.",
                    "SitemapIndexReporter.buildSitemapDoc() maps HttpRequestResponse.httpService().secure() to https or http.");
            case "request.protocol.http_version" -> Tooltips.textWithSource(
                    "HTTP version on the request line.",
                    "SitemapIndexReporter.buildSitemapDoc() uses RequestResponseDocBuilder.safeRequestHttpVersion().");
            case "request.header" -> Tooltips.textWithSource(
                    "Actual request headers as lower-case dynamic fields plus exporter-inferred header facets.",
                    "RequestResponseDocBuilder.buildSitemapRequestDoc() copies HttpHeader values into request.header.<lower-case-name>; duplicate header names become arrays, and inferred request content type is written as request.header.content-type_inferred.");
            case "request.method" -> Tooltips.textWithSource(
                    "HTTP method.",
                    "RequestResponseDocBuilder.buildSitemapRequestDoc() uses HttpRequest.method().");
            case "request.path.with_query" -> Tooltips.textWithSource(
                    "Request path and query portion.",
                    "RequestResponseDocBuilder.buildSitemapRequestDoc() uses HttpRequest.path().");
            case "request.path.without_query" -> Tooltips.textWithSource(
                    "Request path without the query string.",
                    "RequestResponseDocBuilder.buildSitemapRequestDoc() uses HttpRequest.pathWithoutQuery().");
            case "request.path.query" -> Tooltips.textWithSource(
                    "Raw query string from the request URL without the leading ?.",
                    "RequestResponseDocBuilder.buildSitemapRequestDoc() uses HttpRequest.query().");
            case "request.path.file_extension" -> Tooltips.textWithSource(
                    "File extension inferred from the request URL path.",
                    "RequestResponseDocBuilder.buildSitemapRequestDoc() uses HttpRequest.fileExtension().");
            case "response.status.code" -> Tooltips.textWithSource(
                    "HTTP response status code when a response exists.",
                    "RequestResponseDocBuilder.buildTrafficResponseDoc() uses HttpResponse.statusCode() for sitemap responses.");
            case "response.status.code_class" -> Tooltips.textWithSource(
                    "HTTP status family derived from the status code.",
                    "RequestResponseDocBuilder.statusCodeClassName() maps the sitemap response status code to Burp StatusCodeClass.");
            case "response.status.description" -> Tooltips.textWithSource(
                    "HTTP response reason phrase when a response exists.",
                    "RequestResponseDocBuilder.buildTrafficResponseDoc() uses HttpResponse.reasonPhrase() for sitemap responses.");
            case "response.protocol.http_version" -> Tooltips.textWithSource(
                    "HTTP version reported for the response.",
                    "RequestResponseDocBuilder.buildTrafficResponseDoc() uses only HttpResponse.httpVersion().");
            case "response.header" -> Tooltips.textWithSource(
                    "Actual response headers as lower-case dynamic fields plus Burp-inferred content-type facets.",
                    "RequestResponseDocBuilder.buildTrafficResponseDoc() copies HttpHeader values into response.header.<lower-case-name>; duplicate header names become arrays, and Burp MIME verdicts are written as response.header.content-type_inferred_burp and response.header.content-type_inferred_burp_body.");
            case "burp.notes" -> Tooltips.textWithSource(
                    "User notes attached to the sitemap item in Burp.",
                    "SitemapIndexReporter.buildBurpDoc() reads HttpRequestResponse.annotations().notes().");
            case "burp.highlight" -> Tooltips.textWithSource(
                    "Burp highlight color attached to the sitemap item.",
                    "SitemapIndexReporter.buildBurpDoc() reads HttpRequestResponse.annotations().highlightColor().name().");
            case "burp.is_in_scope" -> Tooltips.textWithSource(
                    "Raw Burp Suite scope flag for the sitemap URL, not the extension's export-scope decision.",
                    "SitemapIndexReporter.pushItems() uses MontoyaApi.scope().isInScope(url).");
            case "burp.timing.end" -> Tooltips.textWithSource(
                    "Absolute response-end timestamp for this sitemap HTTP exchange when Burp exposes timing data.",
                    "SitemapIndexReporter.buildTiming() derives this from TimingData.timeRequestSent() plus timeBetweenRequestSentAndEndOfResponse().");
            case "burp.timing.req_sent" -> Tooltips.textWithSource(
                    "Request-sent timestamp for this sitemap HTTP exchange when Burp exposes timing data.",
                    "SitemapIndexReporter.buildTiming() uses HttpRequestResponse.timingData().timeRequestSent().");
            case "burp.timing.req_sent_to_res_start" -> Tooltips.textWithSource(
                    "Time to first response byte in milliseconds: request sent to start of response.",
                    "SitemapIndexReporter.buildTiming() uses HttpRequestResponse.timingData().timeBetweenRequestSentAndStartOfResponse().");
            case "burp.timing.req_sent_to_res_end" -> Tooltips.textWithSource(
                    "Total observed exchange duration in milliseconds: request sent to end of response.",
                    "SitemapIndexReporter.buildTiming() uses HttpRequestResponse.timingData().timeBetweenRequestSentAndEndOfResponse().");
            default -> sitemapTooltipByPattern(fieldKey);
        };
    }

    private static String sitemapTooltipByPattern(String fieldKey) {
        if (fieldKey != null && (fieldKey.startsWith("request.") || fieldKey.startsWith("response."))) {
            String tooltip = requestResponseNestedTooltip(fieldKey);
            if (!tooltip.contains("Included when this toggle is enabled in the Fields panel.")) {
                return tooltip;
            }
        }
        return genericLeafTooltip(fieldKey);
    }

    private static String findingsDisplayName(String fieldKey) {
        return ExportFieldTooltipsFindings.findingsDisplayName(fieldKey);
    }

    private static String findingsTooltip(String fieldKey) {
        return ExportFieldTooltipsFindings.findingsTooltip(fieldKey);
    }

    private static String trafficDisplayName(String fieldKey) {
        return ExportFieldTooltipsTraffic.trafficDisplayName(fieldKey);
    }

    private static String trafficTooltip(String fieldKey) {
        return ExportFieldTooltipsTraffic.trafficTooltip(fieldKey);
    }

    private static String requestResponseNestedTooltip(String fieldKey) {
        return ExportFieldTooltipsRequestResponse.requestResponseNestedTooltip(fieldKey);
    }
}
