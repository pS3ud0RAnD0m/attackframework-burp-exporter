package ai.anomalousvectors.tools.burp.sinks;

import java.util.Arrays;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

/**
 * Detects proxy-side edits and compares Montoya message bytes for single-document export.
 */
final class ProxyEditSupport {

    private ProxyEditSupport() {}

    /**
     * Returns {@code true} when the proxy row is marked edited and stored request bytes differ from
     * the sent request.
     *
     * @param item proxy history row
     * @return {@code true} when the request body was edited in the proxy pipeline
     */
    public static boolean requestWasEdited(ProxyHttpRequestResponse item) {
        if (item == null || !item.edited()) {
            return false;
        }
        HttpRequest sent = item.finalRequest();
        HttpRequest stored = item.request();
        return stored != null && sent != null && !sameMessageBytes(stored, sent);
    }

    /**
     * Returns {@code true} when the proxy row is marked edited and the effective response bytes
     * differ from the original response.
     *
     * @param item proxy history row
     * @return {@code true} when the response body was edited in the proxy pipeline
     */
    public static boolean responseWasEdited(ProxyHttpRequestResponse item) {
        if (item == null || !item.edited() || !item.hasResponse()) {
            return false;
        }
        HttpResponse effective = item.response();
        HttpResponse original = item.originalResponse();
        return effective != null && original != null && !sameMessageBytes(original, effective);
    }

    /**
     * Compares Montoya message wire bytes for equality.
     *
     * @param left first message
     * @param right second message
     * @return {@code true} when both are the same reference or have identical {@code toByteArray()} bytes
     */
    public static boolean sameMessageBytes(HttpMessage left, HttpMessage right) {
        if (left == right) {
            return true;
        }
        if (left == null || right == null) {
            return false;
        }
        return sameByteArrays(left.toByteArray(), right.toByteArray());
    }

    private static boolean sameByteArrays(ByteArray left, ByteArray right) {
        if (left == right) {
            return true;
        }
        if (left == null || right == null) {
            return false;
        }
        byte[] leftBytes = left.getBytes();
        byte[] rightBytes = right.getBytes();
        if (leftBytes == rightBytes) {
            return true;
        }
        if (leftBytes.length != rightBytes.length) {
            return false;
        }
        return Arrays.equals(leftBytes, rightBytes);
    }
}
