package ai.attackframework.tools.burp.ui.text;

/**
 * Shared UI text for generated field checkboxes in the Config "Index Fields" section.
 */
public final class ExportFieldTooltips {

    private ExportFieldTooltips() {}

    public static String displayNameFor(String indexShortName, String fieldKey) {
        return switch (indexShortName) {
            case "settings" -> settingsDisplayName(fieldKey);
            case "sitemap" -> sitemapDisplayName(fieldKey);
            case "findings" -> findingsDisplayName(fieldKey);
            case "traffic" -> trafficDisplayName(fieldKey);
            default -> fieldKey;
        };
    }

    public static String tooltipFor(String indexShortName, String fieldKey) {
        return switch (indexShortName) {
            case "settings" -> settingsTooltip(fieldKey);
            case "sitemap" -> sitemapTooltip(fieldKey);
            case "findings" -> findingsTooltip(fieldKey);
            case "traffic" -> trafficTooltip(fieldKey);
            default -> fieldKey;
        };
    }

    private static String settingsDisplayName(String fieldKey) {
        return switch (fieldKey) {
            case "settings_user" -> "settings.user";
            case "settings_project" -> "settings.project";
            default -> fieldKey;
        };
    }

    private static String settingsTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "project_id" -> Tooltips.textWithSource(
                    "Burp project identifier.",
                    "SettingsIndexReporter uses MontoyaApi.project().id().");
            case "settings_user" -> Tooltips.textWithSource(
                    "Full user options JSON when User settings export is enabled.",
                    "SettingsIndexReporter uses MontoyaApi.burpSuite().exportUserOptionsAsJson().");
            case "settings_project" -> Tooltips.textWithSource(
                    "Full project options JSON when Project settings export is enabled.",
                    "SettingsIndexReporter uses MontoyaApi.burpSuite().exportProjectOptionsAsJson().");
            default -> fieldKey;
        };
    }

    private static String sitemapDisplayName(String fieldKey) {
        return switch (fieldKey) {
            case "url" -> "request.url";
            case "host" -> "request.host";
            case "port" -> "request.port";
            case "protocol_transport" -> "request.protocol_transport";
            case "protocol_application" -> "request.protocol_application";
            case "protocol_sub" -> "request.http_version";
            case "method" -> "request.method";
            case "status_code" -> "response.status";
            case "status_reason" -> "response.reason_phrase";
            case "content_type" -> "response.mime_type";
            case "content_length" -> "response.body.length";
            case "title" -> "response.body.page_title";
            case "param_names" -> "request.parameters.name";
            case "path" -> "request.path";
            case "query_string" -> "request.query";
            default -> fieldKey;
        };
    }

    private static String sitemapTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "url" -> Tooltips.textWithSource(
                    "Full URL for the sitemap item.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.request().url().");
            case "host" -> Tooltips.textWithSource(
                    "Target host.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.httpService().host().");
            case "port" -> Tooltips.textWithSource(
                    "Target port.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.httpService().port().");
            case "protocol_transport" -> Tooltips.textWithSource(
                    "Transport protocol.",
                    "SitemapIndexReporter.buildSitemapDoc() maps HttpRequestResponse.httpService().secure() to https/http.");
            case "protocol_application" -> Tooltips.textWithSource(
                    "Application protocol label.",
                    "SitemapIndexReporter.buildSitemapDoc() assigns constant \"http\".");
            case "protocol_sub" -> Tooltips.textWithSource(
                    "HTTP protocol version.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.request().httpVersion().");
            case "method" -> Tooltips.textWithSource(
                    "HTTP method.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.request().method().");
            case "status_code" -> Tooltips.textWithSource(
                    "HTTP response status code when a response exists.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.response().statusCode().");
            case "status_reason" -> Tooltips.textWithSource(
                    "HTTP response reason phrase when a response exists.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.response().reasonPhrase().");
            case "content_type" -> Tooltips.textWithSource(
                    "Effective response MIME type summary.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.response().mimeType().");
            case "content_length" -> Tooltips.textWithSource(
                    "Response body length in bytes.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.response().body().getBytes().length.");
            case "title" -> Tooltips.textWithSource(
                    "Page title when Burp exposes it.",
                    "SitemapIndexReporter.getPageTitle() uses HttpRequestResponse.response().attributes(AttributeType.PAGE_TITLE).");
            case "param_names" -> Tooltips.textWithSource(
                    "Request parameter names only.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.request().parameters().");
            case "path" -> Tooltips.textWithSource(
                    "Request path and query portion.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.request().path().");
            case "query_string" -> Tooltips.textWithSource(
                    "Raw request query string.",
                    "SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.request().query().");
            case "request_id" -> Tooltips.textWithSource(
                    "Deduplication key for incremental sitemap export.",
                    "Derived from Montoya request.url() and request.method(); SitemapIndexReporter.requestId() computes SHA-256(url + \"|\" + method).");
            case "source" -> Tooltips.textWithSource(
                    "Document source label.",
                    "SitemapIndexReporter.buildSitemapDoc() assigns constant \"burp-exporter\".");
            default -> fieldKey;
        };
    }

    private static String findingsDisplayName(String fieldKey) {
        return switch (fieldKey) {
            case "name" -> "issue.name";
            case "severity" -> "issue.severity";
            case "confidence" -> "issue.confidence";
            case "host" -> "issue.host";
            case "port" -> "issue.port";
            case "protocol_transport" -> "issue.protocol_transport";
            case "protocol_application" -> "issue.protocol_application";
            case "protocol_sub" -> "issue.protocol_sub";
            case "url" -> "issue.url";
            case "param" -> "issue.param";
            case "issue_type_id" -> "issue.definition.type_index";
            case "typical_severity" -> "issue.definition.typical_severity";
            case "description" -> "issue.detail";
            case "background" -> "issue.definition.background";
            case "remediation_background" -> "issue.definition.remediation";
            case "remediation_detail" -> "issue.remediation";
            case "references" -> "issue.references";
            case "classifications" -> "issue.classifications";
            default -> fieldKey;
        };
    }

    private static String findingsTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "name" -> Tooltips.textWithSource(
                    "Issue name.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.name().");
            case "severity" -> Tooltips.textWithSource(
                    "Issue severity.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.severity().");
            case "confidence" -> Tooltips.textWithSource(
                    "Issue confidence.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.confidence().");
            case "host" -> Tooltips.textWithSource(
                    "Target host.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.httpService().host().");
            case "port" -> Tooltips.textWithSource(
                    "Target port.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.httpService().port().");
            case "protocol_transport" -> Tooltips.textWithSource(
                    "Transport protocol.",
                    "FindingsIndexReporter.buildFindingDoc() maps AuditIssue.httpService().secure() to https/http.");
            case "protocol_application" -> Tooltips.textWithSource(
                    "Application protocol label.",
                    "FindingsIndexReporter.buildFindingDoc() currently assigns an empty string; not yet populated from Montoya.");
            case "protocol_sub" -> Tooltips.textWithSource(
                    "Protocol version label.",
                    "FindingsIndexReporter.buildFindingDoc() currently assigns an empty string; not yet populated from Montoya.");
            case "url" -> Tooltips.textWithSource(
                    "Base URL for the finding.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.baseUrl().");
            case "param" -> Tooltips.textWithSource(
                    "Affected parameter.",
                    "FindingsIndexReporter.buildFindingDoc() currently assigns an empty string; parameter extraction is not yet implemented.");
            case "issue_type_id" -> Tooltips.textWithSource(
                    "Burp issue type identifier.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.definition().typeIndex().");
            case "typical_severity" -> Tooltips.textWithSource(
                    "Typical severity from the issue definition.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.definition().typicalSeverity().");
            case "description" -> Tooltips.textWithSource(
                    "Issue description.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.detail().");
            case "background" -> Tooltips.textWithSource(
                    "Issue background text.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.definition().background().");
            case "remediation_background" -> Tooltips.textWithSource(
                    "Remediation background text.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.definition().remediation().");
            case "remediation_detail" -> Tooltips.textWithSource(
                    "Remediation detail text.",
                    "FindingsIndexReporter.buildFindingDoc() uses AuditIssue.remediation().");
            case "references" -> Tooltips.textWithSource(
                    "Issue references.",
                    "FindingsIndexReporter.buildFindingDoc() currently assigns an empty string; reference extraction is not yet implemented.");
            case "classifications" -> Tooltips.textWithSource(
                    "Issue classifications such as CWE/CAPEC.",
                    "FindingsIndexReporter.buildFindingDoc() currently assigns an empty object; classification extraction is not yet implemented.");
            default -> fieldKey;
        };
    }

    private static String trafficDisplayName(String fieldKey) {
        return switch (fieldKey) {
            case "url" -> "request.url";
            case "host" -> "request.host";
            case "port" -> "request.port";
            case "scheme" -> "request.scheme";
            case "protocol_transport" -> "request.protocol_transport";
            case "protocol_application" -> "request.protocol_application";
            case "protocol_sub" -> "request.http_version";
            case "http_version" -> "request.http_version";
            case "tool" -> "burp.tool";
            case "tool_type" -> "burp.tool_type";
            case "burp_in_scope" -> "burp_in_scope";
            case "message_id" -> "burp.message_id";
            case "time_start" -> "timing.start";
            case "time_end" -> "timing.end";
            case "duration_ms" -> "timing.duration_ms";
            case "comment" -> "burp.annotations.comment";
            case "highlight" -> "burp.annotations.highlight";
            case "edited" -> "burp.message.edited";
            case "path" -> "request.path";
            case "method" -> "request.method";
            case "mime_type" -> "response.mime_type";
            case "websocket_id" -> "websocket.connection_id";
            case "ws_message_id" -> "websocket.message_id";
            case "ws_direction" -> "websocket.direction";
            case "ws_message_type" -> "websocket.payload_type";
            case "ws_payload" -> "websocket.payload.b64";
            case "ws_payload_text" -> "websocket.payload.text";
            case "ws_payload_length" -> "websocket.payload.length";
            case "ws_edited" -> "websocket.payload.edited";
            case "ws_edited_payload" -> "websocket.payload.edited_b64";
            case "ws_upgrade_request" -> "websocket.upgrade_request";
            case "ws_time" -> "websocket.time";
            case "proxy_history_id" -> "proxy_history.id";
            case "listener_port" -> "proxy.listener_port";
            case "time_request_sent" -> "timing.request_sent";
            case "response_start_latency_ms" -> "timing.response_start_latency_ms";
            default -> fieldKey;
        };
    }

    private static String trafficTooltip(String fieldKey) {
        return switch (fieldKey) {
            case "url" -> Tooltips.textWithSource(
                    "Full request URL.",
                    "OpenSearchTrafficHandler.buildDocument() uses request.url(); ProxyHistoryIndexReporter.buildDocument() uses item.finalRequest().url(); ProxyWebSocketIndexReporter.buildDocument() uses ws.upgradeRequest().url().");
            case "host" -> Tooltips.textWithSource(
                    "Target host.",
                    "Traffic producers use request/upgrade HttpService.host().");
            case "port" -> Tooltips.textWithSource(
                    "Target port.",
                    "Traffic producers use request/upgrade HttpService.port().");
            case "scheme" -> Tooltips.textWithSource(
                    "Request scheme: https or http.",
                    "Traffic producers map request/upgrade HttpService.secure() to https/http.");
            case "protocol_transport" -> Tooltips.textWithSource(
                    "Transport protocol.",
                    "Traffic producers map request/upgrade HttpService.secure() to https/http.");
            case "protocol_application" -> Tooltips.textWithSource(
                    "Application protocol label.",
                    "OpenSearchTrafficHandler.buildDocument() assigns \"http\" for HTTP docs; ProxyHistoryIndexReporter.buildDocument() assigns \"http\"; ProxyWebSocketIndexReporter.buildDocument() assigns \"websocket\".");
            case "protocol_sub" -> Tooltips.textWithSource(
                    "HTTP protocol version.",
                    "HTTP docs use request.httpVersion(); WebSocket docs use ws.upgradeRequest().httpVersion().");
            case "http_version" -> Tooltips.textWithSource(
                    "Top-level HTTP version summary.",
                    "HTTP docs use request.httpVersion(); WebSocket docs use ws.upgradeRequest().httpVersion().");
            case "tool" -> Tooltips.textWithSource(
                    "Burp tool display name.",
                    "OpenSearchTrafficHandler uses ToolType.toolName() from response.toolSource() with request fallback; ProxyHistoryIndexReporter writes \"Proxy History\"; ProxyWebSocketIndexReporter writes \"Proxy WebSocket\".");
            case "tool_type" -> Tooltips.textWithSource(
                    "Burp tool enum/source label.",
                    "OpenSearchTrafficHandler uses ToolType.name() from response.toolSource() with request fallback; ProxyHistoryIndexReporter writes \"PROXY_HISTORY\"; ProxyWebSocketIndexReporter writes \"PROXY_WEBSOCKET\".");
            case "burp_in_scope" -> Tooltips.textWithSource(
                    "Raw Burp Suite scope flag, not the extension's export-scope decision.",
                    "OpenSearchTrafficHandler uses request.isInScope(); ProxyHistoryIndexReporter uses MontoyaApi.scope().isInScope(url); ProxyWebSocketIndexReporter uses MontoyaApi.scope().isInScope(url) via safeBurpInScope().");
            case "message_id" -> Tooltips.textWithSource(
                    "Source-specific Burp message identifier used for correlation.",
                    "OpenSearchTrafficHandler uses response.messageId() or request.messageId() for orphan docs; ProxyHistoryIndexReporter uses ProxyHttpRequestResponse.id(); ProxyWebSocketIndexReporter uses ProxyWebSocketMessage.id().");
            case "time_start" -> Tooltips.textWithSource(
                    "Start time for the exported traffic event.",
                    "OpenSearchTrafficHandler uses an exporter timestamp captured with System.currentTimeMillis() when the request is sent; ProxyHistoryIndexReporter uses TimingData.timeRequestSent() with item.time() fallback; ProxyWebSocketIndexReporter uses ProxyWebSocketMessage.time().");
            case "time_end" -> Tooltips.textWithSource(
                    "End time for the exported traffic event.",
                    "OpenSearchTrafficHandler uses an exporter timestamp captured with System.currentTimeMillis() when the response is received; ProxyHistoryIndexReporter derives it from TimingData.timeRequestSent() plus timeBetweenRequestSentAndEndOfResponse(); ProxyWebSocketIndexReporter reuses ProxyWebSocketMessage.time().");
            case "duration_ms" -> Tooltips.textWithSource(
                    "Observed duration in milliseconds.",
                    "OpenSearchTrafficHandler subtracts exporter-captured request/response timestamps; ProxyHistoryIndexReporter uses TimingData.timeBetweenRequestSentAndEndOfResponse(); ProxyWebSocketIndexReporter writes 0.");
            case "comment" -> Tooltips.textWithSource(
                    "User comment attached in Burp.",
                    "HTTP docs read annotations.notes(); WebSocket docs read ProxyWebSocketMessage.annotations().notes().");
            case "highlight" -> Tooltips.textWithSource(
                    "Burp highlight color.",
                    "HTTP docs read annotations.highlightColor().name(); WebSocket docs read ProxyWebSocketMessage.annotations().highlightColor().name().");
            case "edited" -> Tooltips.textWithSource(
                    "Whether Burp shows the message as edited.",
                    "ProxyHistoryIndexReporter uses ProxyHttpRequestResponse.edited(); ProxyWebSocketIndexReporter writes editedPayload() != null; live HTTP docs currently write null.");
            case "path" -> Tooltips.textWithSource(
                    "Request path and query portion.",
                    "HTTP docs use request.path(); WebSocket docs use ws.upgradeRequest().path().");
            case "method" -> Tooltips.textWithSource(
                    "HTTP method.",
                    "HTTP docs use request.method(); WebSocket docs use ws.upgradeRequest().method().");
            case "mime_type" -> Tooltips.textWithSource(
                    "Effective response MIME classification.",
                    "OpenSearchTrafficHandler and ProxyHistoryIndexReporter use response.mimeType().name(); WebSocket docs write null.");
            case "websocket_id" -> Tooltips.textWithSource(
                    "WebSocket conversation identifier.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.webSocketId().");
            case "ws_message_id" -> Tooltips.textWithSource(
                    "WebSocket message identifier.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.id().");
            case "ws_direction" -> Tooltips.textWithSource(
                    "WebSocket message direction.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.direction().name().");
            case "ws_message_type" -> Tooltips.textWithSource(
                    "Exporter payload classification for a WebSocket message.",
                    "ProxyWebSocketIndexReporter.inferPayloadType() returns EMPTY for no bytes, TEXT for strict UTF-8 decodes, otherwise BINARY.");
            case "ws_payload" -> Tooltips.textWithSource(
                    "Raw WebSocket payload stored as base64.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.payload().getBytes() and Base64 encodes them.");
            case "ws_payload_text" -> Tooltips.textWithSource(
                    "UTF-8 text view of the WebSocket payload when valid.",
                    "ProxyWebSocketIndexReporter.decodeUtf8OrNull() strictly decodes ProxyWebSocketMessage.payload().");
            case "ws_payload_length" -> Tooltips.textWithSource(
                    "WebSocket payload length in bytes.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.payload().getBytes().length.");
            case "ws_edited" -> Tooltips.textWithSource(
                    "Whether the WebSocket payload was edited.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.editedPayload() != null.");
            case "ws_edited_payload" -> Tooltips.textWithSource(
                    "Edited WebSocket payload stored as base64.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.editedPayload().getBytes() and Base64 encodes them.");
            case "ws_upgrade_request" -> Tooltips.textWithSource(
                    "HTTP upgrade request for the WebSocket handshake.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses RequestResponseDocBuilder.buildRequestDoc(ws.upgradeRequest()).");
            case "ws_time" -> Tooltips.textWithSource(
                    "WebSocket message timestamp.",
                    "ProxyWebSocketIndexReporter.buildDocument() uses ProxyWebSocketMessage.time().");
            case "proxy_history_id" -> Tooltips.textWithSource(
                    "Proxy History row identifier.",
                    "ProxyHistoryIndexReporter.buildDocument() uses ProxyHttpRequestResponse.id().");
            case "listener_port" -> Tooltips.textWithSource(
                    "Proxy listener port used for the message.",
                    "ProxyHistoryIndexReporter uses ProxyHttpRequestResponse.listenerPort(); ProxyWebSocketIndexReporter uses ProxyWebSocketMessage.listenerPort().");
            case "time_request_sent" -> Tooltips.textWithSource(
                    "Request-sent timestamp.",
                    "OpenSearchTrafficHandler reuses the exporter timestamp captured when handleHttpRequestToBeSent runs; ProxyHistoryIndexReporter uses TimingData.timeRequestSent() with item.time() fallback; ProxyWebSocketIndexReporter reuses ProxyWebSocketMessage.time().");
            case "response_start_latency_ms" -> Tooltips.textWithSource(
                    "Latency from request sent to response start.",
                    "ProxyHistoryIndexReporter uses TimingData.timeBetweenRequestSentAndStartOfResponse(); OpenSearchTrafficHandler currently stores the full exporter-observed request-to-response delta; ProxyWebSocketIndexReporter writes null.");
            default -> fieldKey;
        };
    }
}
