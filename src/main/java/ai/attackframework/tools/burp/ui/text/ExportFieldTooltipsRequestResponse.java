package ai.attackframework.tools.burp.ui.text;

/**
 * Request/response nested field tooltips shared by traffic, sitemap, and findings evidence paths.
 */
final class ExportFieldTooltipsRequestResponse {

    private ExportFieldTooltipsRequestResponse() { }
    static String requestResponseNestedTooltip(String fieldKey) {
        if (fieldKey == null) {
            return ExportFieldTooltips.genericLeafTooltip(fieldKey);
        }
        if (fieldKey.startsWith("request.body.markers.")) {
            return requestMarkerFieldTooltip(fieldKey.substring("request.body.markers.".length()));
        }
        if (fieldKey.startsWith("request.body.")) {
            return requestBodyFieldTooltip(fieldKey.substring("request.body.".length()));
        }
        if (fieldKey.startsWith("response.body.markers.")) {
            return responseMarkerFieldTooltip(fieldKey.substring("response.body.markers.".length()));
        }
        if (fieldKey.startsWith("response.body.html.")) {
            return responseBodyHtmlFieldTooltip(fieldKey.substring("response.body.html.".length()));
        }
        if (fieldKey.startsWith("response.body.")) {
            return responseBodyFieldTooltip(fieldKey.substring("response.body.".length()));
        }
        if (fieldKey.startsWith("request.markers.")) {
            return requestMarkerFieldTooltip(fieldKey.substring("request.markers.".length()));
        }
        if (fieldKey.startsWith("response.markers.")) {
            return responseMarkerFieldTooltip(fieldKey.substring("response.markers.".length()));
        }
        if (fieldKey.startsWith("request.parameters.")) {
            return requestParameterFieldTooltip(fieldKey.substring("request.parameters.".length()));
        }
        if (fieldKey.startsWith("request.headers.full.")) {
            return requestHeaderEntryFieldTooltip(fieldKey.substring("request.headers.full.".length()));
        }
        if (fieldKey.startsWith("response.headers.full.")) {
            return responseHeaderEntryFieldTooltip(fieldKey.substring("response.headers.full.".length()));
        }
        if (fieldKey.startsWith("response.cookies.")) {
            return responseCookieFieldTooltip(fieldKey.substring("response.cookies.".length()));
        }
        return switch (fieldKey) {
            case "request.method" -> Tooltips.textWithSource(
                    "HTTP method.",
                    "RequestResponseDocBuilder.buildTrafficRequestDoc() uses HttpRequest.method().");
            case "request.path" -> Tooltips.textWithSource(
                    "Request path and query portion (legacy flat field).",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildRequestDoc(), which uses HttpRequest.path().");
            case "response.status_code" -> Tooltips.textWithSource(
                    "Obtain the HTTP status code contained in the response.",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildResponseDoc(), which uses HttpResponse.statusCode().");
            case "response.status_description" -> Tooltips.textWithSource(
                    "Obtain the HTTP reason phrase contained in the response for HTTP 1 messages.",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildResponseDoc(), which uses HttpResponse.reasonPhrase().");
            case "response.mime_type" -> Tooltips.textWithSource(
                    "Obtain the MIME type of the response, as determined by Burp Suite.",
                    "Sitemap and findings evidence use HttpResponse.mimeType().name() in RequestResponseDocBuilder.buildResponseDoc().");
            case "response.stated_mime_type" -> Tooltips.textWithSource(
                    "Obtain the MIME type of the response, as stated in the HTTP headers.",
                    "Sitemap and findings evidence use HttpResponse.statedMimeType().name() in RequestResponseDocBuilder.buildResponseDoc().");
            case "response.inferred_mime_type" -> Tooltips.textWithSource(
                    "Obtain the MIME type of the response, as inferred from the contents of the HTTP message body.",
                    "Sitemap and findings evidence use HttpResponse.inferredMimeType().name() in RequestResponseDocBuilder.buildResponseDoc().");
            case "request.content_type" -> Tooltips.textWithSource(
                    "Burp ContentType string for the request (legacy flat field; duplicates enum name).",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildRequestDoc(), which uses HttpRequest.contentType().toString().");
            case "request.content_type_enum" -> Tooltips.textWithSource(
                    "Burp ContentType enum constant for the request (for example URL_ENCODED).",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildRequestDoc(), which uses HttpRequest.contentType().name().");
            case "request.file_extension" -> Tooltips.textWithSource(
                    "File extension inferred from the request URL path (legacy flat field).",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildRequestDoc(), which uses HttpRequest.fileExtension().");
            case "request.http_version" -> Tooltips.textWithSource(
                    "HTTP version on the request line (for example HTTP/1.1).",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildRequestDoc(), which reads HttpRequest.httpVersion().");
            case "request.inferred_content_type" -> Tooltips.textWithSource(
                    "Exporter-inferred request payload class from body bytes (legacy flat field).",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildRequestDoc() and inferRequestContentType() on request body bytes.");
            case "request.path_without_query" -> Tooltips.textWithSource(
                    "Request path without the query string (legacy flat field).",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildRequestDoc(), which uses HttpRequest.pathWithoutQuery().");
            case "request.query" -> Tooltips.textWithSource(
                    "Raw query string from the request URL (legacy flat field).",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildRequestDoc(), which uses HttpRequest.query().");
            case "response.http_version" -> Tooltips.textWithSource(
                    "HTTP version on the response status line.",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.buildResponseDoc(), which reads HttpResponse.httpVersion().");
            case "response.status_code_class" -> Tooltips.textWithSource(
                    "HTTP status family derived from the status code (for example 2xx, 4xx).",
                    "Sitemap and findings evidence use RequestResponseDocBuilder.statusCodeClassName() on HttpResponse.statusCode().");
            case "response.headers.names" -> Tooltips.textWithSource(
                    "Ordered list of response header names.",
                    "RequestResponseDocBuilder.buildResponseDoc() uses headerNames(HttpResponse.headers()) under response.headers.names.");
            case "response.headers.etag" -> Tooltips.textWithSource(
                    "ETag response header value when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.ETAG_HEADER) into response.headers.etag.");
            case "response.headers.last_modified" -> Tooltips.textWithSource(
                    "Last-Modified response header value when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.LAST_MODIFIED_HEADER) into response.headers.last_modified.");
            case "response.headers.content_location" -> Tooltips.textWithSource(
                    "Content-Location response header value when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CONTENT_LOCATION) into response.headers.content_location.");
            case "response.location" -> Tooltips.textWithSource(
                    "Location response header value (redirect target).",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.LOCATION).");
            case "response.content_length" -> Tooltips.textWithSource(
                    "Content-Length header value when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CONTENT_LENGTH).");
            case "response.cookie_names" -> Tooltips.textWithSource(
                    "Cookie names set on the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.COOKIE_NAMES).");
            case "response.canonical_link" -> Tooltips.textWithSource(
                    "Canonical link URL parsed from HTML when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CANONICAL_LINK).");
            case "response.comments" -> Tooltips.textWithSource(
                    "HTML comments extracted from the response body.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.COMMENTS).");
            case "response.non_hidden_form_input_types" -> Tooltips.textWithSource(
                    "Non-hidden HTML form input types present in the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.NON_HIDDEN_FORM_INPUT_TYPES).");
            case "response.input_submit_labels" -> Tooltips.textWithSource(
                    "Labels of submit inputs in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.INPUT_SUBMIT_LABELS).");
            case "response.button_submit_labels" -> Tooltips.textWithSource(
                    "Labels of submit buttons in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.BUTTON_SUBMIT_LABELS).");
            case "response.input_image_labels" -> Tooltips.textWithSource(
                    "Alt text of image submit inputs in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.INPUT_IMAGE_LABELS).");
            case "response.outbound_edge_count" -> Tooltips.textWithSource(
                    "Count of outbound links/edges Burp parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_COUNT).");
            case "response.outbound_edge_tag_names" -> Tooltips.textWithSource(
                    "Tag names of outbound edges parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_TAG_NAMES).");
            default -> ExportFieldTooltips.genericLeafTooltip(fieldKey);
        };
    }

    static String requestBodyFieldTooltip(String leaf) {
        return switch (leaf) {
            case "b64" -> Tooltips.textWithSource(
                    "Raw request body bytes as Base64 for exact replay.",
                    "RequestResponseDocBuilder.putBodyFields() Base64-encodes HttpRequest.body().getBytes() when the body is non-empty.");
            case "length" -> Tooltips.textWithSource(
                    "Request body length in bytes.",
                    "RequestResponseDocBuilder.putBodyFields() uses HttpRequest.body().getBytes().length (0 when absent).");
            case "offset" -> Tooltips.textWithSource(
                    "Byte offset of the request body within the raw HTTP message.",
                    "RequestResponseDocBuilder.putBodyFields() uses HttpRequest.bodyOffset().");
            case "text" -> Tooltips.textWithSource(
                    "Decoded request body text when the exporter classifies the payload as searchable text.",
                    "RequestResponseDocBuilder.extractBodyText() decodes bytes using Content-Type, Burp MIME hints, and byte sniffing; null for binary or compressed bodies.");
            case "markers" -> Tooltips.textWithSource(
                    "Burp request highlight marker ranges.",
                    "RequestResponseDocBuilder.markersToList() copies HttpRequest.markers() into request.body.markers.");
            default -> ExportFieldTooltips.genericLeafTooltip("request.body." + leaf);
        };
    }

    static String responseBodyFieldTooltip(String leaf) {
        return switch (leaf) {
            case "b64" -> Tooltips.textWithSource(
                    "Raw response body bytes as Base64 for exact replay.",
                    "RequestResponseDocBuilder.putBodyFields() Base64-encodes HttpResponse.body().getBytes() when the body is non-empty.");
            case "length" -> Tooltips.textWithSource(
                    "Response body length in bytes.",
                    "RequestResponseDocBuilder.putBodyFields() uses HttpResponse.body().getBytes().length (0 when absent).");
            case "offset" -> Tooltips.textWithSource(
                    "Byte offset of the response body within the raw HTTP message.",
                    "RequestResponseDocBuilder.putBodyFields() uses HttpResponse.bodyOffset().");
            case "text" -> Tooltips.textWithSource(
                    "Decoded response body text when classified as searchable text.",
                    "RequestResponseDocBuilder.extractBodyText() decodes bytes using Content-Type and Burp MIME hints; null for binary or compressed bodies.");
            case "page_title" -> Tooltips.textWithSource(
                    "HTML page title parsed from the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.PAGE_TITLE) into response.body.page_title.");
            case "visible_text" -> Tooltips.textWithSource(
                    "Visible text content extracted from HTML.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.VISIBLE_TEXT) into response.body.visible_text.");
            case "word_count" -> Tooltips.textWithSource(
                    "Word count of the full response body text.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.WORD_COUNT) into response.body.word_count.");
            case "visible_word_count" -> Tooltips.textWithSource(
                    "Word count of visible text in HTML responses.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.VISIBLE_WORD_COUNT) into response.body.visible_word_count.");
            case "line_count" -> Tooltips.textWithSource(
                    "Line count of the response body text.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.LINE_COUNT) into response.body.line_count.");
            case "anchor_labels" -> Tooltips.textWithSource(
                    "Text labels of HTML anchor elements.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.ANCHOR_LABELS) into response.body.anchor_labels.");
            case "button_submit_labels" -> Tooltips.textWithSource(
                    "Labels of submit buttons in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.BUTTON_SUBMIT_LABELS) into response.body.button_submit_labels.");
            case "canonical_link" -> Tooltips.textWithSource(
                    "Canonical link URL parsed from HTML when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CANONICAL_LINK) into response.body.canonical_link.");
            case "comments" -> Tooltips.textWithSource(
                    "HTML comments extracted from the response body.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.COMMENTS) into response.body.comments.");
            case "tag_names" -> Tooltips.textWithSource(
                    "HTML tag names present in the response body.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.TAG_NAMES) into response.body.tag_names.");
            case "div_ids" -> Tooltips.textWithSource(
                    "HTML div id attributes found in the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.DIV_IDS) into response.body.div_ids.");
            case "css_classes" -> Tooltips.textWithSource(
                    "CSS class names found in the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CSS_CLASSES) into response.body.css_classes.");
            case "input_image_labels" -> Tooltips.textWithSource(
                    "Alt text of image submit inputs in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.INPUT_IMAGE_LABELS) into response.body.input_image_labels.");
            case "markers" -> Tooltips.textWithSource(
                    "Burp response highlight marker ranges.",
                    "RequestResponseDocBuilder.markersToList() copies HttpResponse.markers() into response.body.markers.");
            case "non_hidden_form_input_types" -> Tooltips.textWithSource(
                    "Non-hidden HTML form input types present in the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.NON_HIDDEN_FORM_INPUT_TYPES) into response.body.non_hidden_form_input_types.");
            case "outbound_edge_count" -> Tooltips.textWithSource(
                    "Count of outbound links/edges Burp parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_COUNT) into response.body.outbound_edge_count.");
            case "outbound_edge_tag_names" -> Tooltips.textWithSource(
                    "Tag names of outbound edges parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_TAG_NAMES) into response.body.outbound_edge_tag_names.");
            default -> ExportFieldTooltips.genericLeafTooltip("response.body." + leaf);
        };
    }

    static String responseBodyHtmlFieldTooltip(String leaf) {
        return switch (leaf) {
            case "page_title" -> Tooltips.textWithSource(
                    "HTML page title parsed from the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.PAGE_TITLE) into response.body.html.page_title.");
            case "text.visible_text" -> Tooltips.textWithSource(
                    "Visible text content extracted from HTML.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.VISIBLE_TEXT) into response.body.html.text.visible_text.");
            case "text.visible_word_count" -> Tooltips.textWithSource(
                    "Word count of visible text in HTML responses.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.VISIBLE_WORD_COUNT) into response.body.html.text.visible_word_count.");
            case "links.anchor_labels" -> Tooltips.textWithSource(
                    "Text labels of HTML anchor elements.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.ANCHOR_LABELS) into response.body.html.links.anchor_labels.");
            case "forms.button_submit_labels" -> Tooltips.textWithSource(
                    "Labels of submit buttons in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.BUTTON_SUBMIT_LABELS) into response.body.html.forms.button_submit_labels.");
            case "links.canonical_link" -> Tooltips.textWithSource(
                    "Canonical link URL parsed from HTML when present.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CANONICAL_LINK) into response.body.html.links.canonical_link.");
            case "comments" -> Tooltips.textWithSource(
                    "HTML comments extracted from the response body.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.COMMENTS) into response.body.html.comments.");
            case "dom.tag_names" -> Tooltips.textWithSource(
                    "HTML tag names present in the response body.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.TAG_NAMES) into response.body.html.dom.tag_names.");
            case "dom.div_ids" -> Tooltips.textWithSource(
                    "HTML div id attributes found in the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.DIV_IDS) into response.body.html.dom.div_ids.");
            case "dom.css_classes" -> Tooltips.textWithSource(
                    "CSS class names found in the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.CSS_CLASSES) into response.body.html.dom.css_classes.");
            case "forms.input_image_labels" -> Tooltips.textWithSource(
                    "Alt text of image submit inputs in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.INPUT_IMAGE_LABELS) into response.body.html.forms.input_image_labels.");
            case "forms.input_submit_labels" -> Tooltips.textWithSource(
                    "Labels of submit inputs in HTML forms.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.INPUT_SUBMIT_LABELS) into response.body.html.forms.input_submit_labels.");
            case "forms.non_hidden_form_input_types" -> Tooltips.textWithSource(
                    "Non-hidden HTML form input types present in the response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.NON_HIDDEN_FORM_INPUT_TYPES) into response.body.html.forms.non_hidden_form_input_types.");
            case "links.outbound_edge_count" -> Tooltips.textWithSource(
                    "Count of outbound links/edges Burp parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_COUNT) into response.body.html.links.outbound_edge_count.");
            case "links.outbound_edge_tag_names" -> Tooltips.textWithSource(
                    "Tag names of outbound edges parsed from the HTML response.",
                    "RequestResponseDocBuilder.putResponseAttributes() reads HttpResponseReceived.attributes(AttributeType.OUTBOUND_EDGE_TAG_NAMES) into response.body.html.links.outbound_edge_tag_names.");
            default -> ExportFieldTooltips.genericLeafTooltip("response.body.html." + leaf);
        };
    }

    static String requestMarkerFieldTooltip(String leaf) {
        return switch (leaf) {
            case "start_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a Burp request body highlight marker.",
                    "RequestResponseDocBuilder.trafficMarkersToList() copies Marker.range().startIndexInclusive() from HttpRequest.markers() into request.body.markers.start_inclusive.");
            case "end_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a Burp request body highlight marker.",
                    "RequestResponseDocBuilder.trafficMarkersToList() copies Marker.range().endIndexExclusive() from HttpRequest.markers() into request.body.markers.end_exclusive.");
            case "start_index_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a Burp request highlight marker.",
                    "RequestResponseDocBuilder.markersToList() copies Marker.range().startIndexInclusive() from HttpRequest.markers().");
            case "end_index_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a Burp request highlight marker.",
                    "RequestResponseDocBuilder.markersToList() copies Marker.range().endIndexExclusive() from HttpRequest.markers().");
            default -> ExportFieldTooltips.genericLeafTooltip("request.markers." + leaf);
        };
    }

    static String responseMarkerFieldTooltip(String leaf) {
        return switch (leaf) {
            case "start_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a Burp response body highlight marker.",
                    "RequestResponseDocBuilder.trafficMarkersToList() copies Marker.range().startIndexInclusive() from HttpResponse.markers() into response.body.markers.start_inclusive.");
            case "end_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a Burp response body highlight marker.",
                    "RequestResponseDocBuilder.trafficMarkersToList() copies Marker.range().endIndexExclusive() from HttpResponse.markers() into response.body.markers.end_exclusive.");
            case "start_index_inclusive" -> Tooltips.textWithSource(
                    "Inclusive start offset of a Burp response highlight marker.",
                    "RequestResponseDocBuilder.markersToList() copies Marker.range().startIndexInclusive() from HttpResponse.markers().");
            case "end_index_exclusive" -> Tooltips.textWithSource(
                    "Exclusive end offset of a Burp response highlight marker.",
                    "RequestResponseDocBuilder.markersToList() copies Marker.range().endIndexExclusive() from HttpResponse.markers().");
            default -> ExportFieldTooltips.genericLeafTooltip("response.markers." + leaf);
        };
    }

    static String requestParameterFieldTooltip(String leaf) {
        return switch (leaf) {
            case "name" -> Tooltips.textWithSource(
                    "Parsed HTTP parameter name.",
                    "RequestResponseDocBuilder.parametersToList() uses ParsedHttpParameter.name() from HttpRequest.parameters(); BODY parameters may be filtered on binary bodies.");
            case "type" -> Tooltips.textWithSource(
                    "Burp parameter type (URL, BODY, COOKIE, JSON, XML, etc.).",
                    "RequestResponseDocBuilder.parametersToList() uses ParsedHttpParameter.type().name().");
            case "value" -> Tooltips.textWithSource(
                    "Parsed HTTP parameter value.",
                    "RequestResponseDocBuilder.parametersToList() uses ParsedHttpParameter.value().");
            default -> ExportFieldTooltips.genericLeafTooltip("request.parameters." + leaf);
        };
    }

    static String requestHeaderEntryFieldTooltip(String leaf) {
        return switch (leaf) {
            case "name" -> Tooltips.textWithSource(
                    "Request header name.",
                    "RequestResponseDocBuilder.buildHeadersObject() copies HttpHeader.name() into request.headers.full nested entries.");
            case "value" -> Tooltips.textWithSource(
                    "Request header value.",
                    "RequestResponseDocBuilder.buildHeadersObject() copies HttpHeader.value() into request.headers.full nested entries.");
            default -> ExportFieldTooltips.genericLeafTooltip("request.headers.full." + leaf);
        };
    }

    static String responseHeaderEntryFieldTooltip(String leaf) {
        return switch (leaf) {
            case "name" -> Tooltips.textWithSource(
                    "Response header name.",
                    "RequestResponseDocBuilder.buildHeadersObject() copies HttpHeader.name() into response.headers.full nested entries.");
            case "value" -> Tooltips.textWithSource(
                    "Response header value.",
                    "RequestResponseDocBuilder.buildHeadersObject() copies HttpHeader.value() into response.headers.full nested entries.");
            default -> ExportFieldTooltips.genericLeafTooltip("response.headers.full." + leaf);
        };
    }

    static String responseCookieFieldTooltip(String leaf) {
        return switch (leaf) {
            case "name" -> Tooltips.textWithSource(
                    "Set-Cookie name.",
                    "RequestResponseDocBuilder.cookiesToList() uses burp.api.montoya.http.message.Cookie.name().");
            case "value" -> Tooltips.textWithSource(
                    "Set-Cookie value.",
                    "RequestResponseDocBuilder.cookiesToList() uses Cookie.value().");
            case "domain" -> Tooltips.textWithSource(
                    "Cookie domain attribute.",
                    "RequestResponseDocBuilder.cookiesToList() uses Cookie.domain().");
            case "path" -> Tooltips.textWithSource(
                    "Cookie path attribute.",
                    "RequestResponseDocBuilder.cookiesToList() uses Cookie.path().");
            case "expiration" -> Tooltips.textWithSource(
                    "Cookie expiration instant when provided.",
                    "RequestResponseDocBuilder.cookiesToList() uses Cookie.expiration() converted to Instant.toString().");
            default -> ExportFieldTooltips.genericLeafTooltip("response.cookies." + leaf);
        };
    }
}
