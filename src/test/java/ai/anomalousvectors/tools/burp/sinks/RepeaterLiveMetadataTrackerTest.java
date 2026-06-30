package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.getStaticConcurrentHashMap;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.junit.jupiter.api.Test;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

class RepeaterLiveMetadataTrackerTest {

    @Test
    void resolveForExchange_returnsMetadata_whenRecentAndUnique() {
        RepeaterLiveMetadataTracker.clear();
        try {
            HttpRequestResponse exchange = requestResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            RepeaterMetadataFields.Metadata metadata =
                    new RepeaterMetadataFields.Metadata("myRepeaterTab", "myRepeaterGroup");

            RepeaterLiveMetadataTracker.observe(exchange, metadata, 1_000L);

            assertThat(RepeaterLiveMetadataTracker.resolveExchangeResolution(
                    exchange.request(),
                    exchange.response(),
                    1_500L).metadata()).isEqualTo(metadata);
            assertThat(RepeaterLiveMetadataTracker.resolveExchangeResolution(
                    exchange.request(),
                    exchange.response(),
                    1_500L).sourceLabel()).isEqualTo(RepeaterMetadataTraceLabels.EXCHANGE_HASH);
            assertThat(RepeaterLiveMetadataTracker.resolveRequestResolution(exchange.request(), 1_500L).metadata())
                    .isEqualTo(metadata);
            assertThat(RepeaterLiveMetadataTracker.resolveRequestResolution(exchange.request(), 1_500L).sourceLabel())
                    .isEqualTo(RepeaterMetadataTraceLabels.REQUEST_IDENTITY);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveForRequest_returnsExactMetadata_whenObservedRequestIdentityMatches() {
        RepeaterLiveMetadataTracker.clear();
        try {
            HttpRequestResponse first = requestResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            HttpRequestResponse second = requestResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB");

            RepeaterLiveMetadataTracker.observe(
                    first,
                    new RepeaterMetadataFields.Metadata("tab-one", "group-one"),
                    1_000L);
            RepeaterLiveMetadataTracker.observe(
                    second,
                    new RepeaterMetadataFields.Metadata("tab-two", "group-two"),
                    1_001L);

            RepeaterLiveMetadataTracker.Resolution requestResolution =
                    RepeaterLiveMetadataTracker.resolveRequestResolution(first.request(), 1_500L);
            RepeaterLiveMetadataTracker.Resolution exchangeResolution =
                    RepeaterLiveMetadataTracker.resolveExchangeResolution(first.request(), first.response(), 1_500L);

            assertThat(requestResolution.ambiguous()).isFalse();
            assertThat(requestResolution.metadata())
                    .isEqualTo(new RepeaterMetadataFields.Metadata("tab-one", "group-one"));
            assertThat(requestResolution.sourceLabel()).isEqualTo(RepeaterMetadataTraceLabels.REQUEST_IDENTITY);
            assertThat(exchangeResolution.metadata())
                    .isEqualTo(new RepeaterMetadataFields.Metadata("tab-one", "group-one"));
            assertThat(exchangeResolution.sourceLabel()).isEqualTo(RepeaterMetadataTraceLabels.EXCHANGE_HASH);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveForRequest_returnsEmpty_whenIdentityMissesAndDistinctTabsShareSameRequestBytes() {
        RepeaterLiveMetadataTracker.clear();
        try {
            HttpRequestResponse first = requestResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            HttpRequestResponse second = requestResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB");
            HttpRequestResponse third = requestResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nC");

            RepeaterLiveMetadataTracker.observe(
                    first,
                    new RepeaterMetadataFields.Metadata("tab-one", "group-one"),
                    1_000L);
            RepeaterLiveMetadataTracker.observe(
                    second,
                    new RepeaterMetadataFields.Metadata("tab-two", "group-two"),
                    1_001L);

            RepeaterLiveMetadataTracker.Resolution requestResolution =
                    RepeaterLiveMetadataTracker.resolveRequestResolution(third.request(), 1_500L);

            assertThat(requestResolution.ambiguous()).isTrue();
            assertThat(requestResolution.metadata()).isEqualTo(RepeaterMetadataFields.Metadata.empty());
            assertThat(requestResolution.sourceLabel()).isEqualTo(RepeaterMetadataTraceLabels.REQUEST_HASH);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveForExchange_returnsEmpty_afterFreshnessWindowExpires() {
        RepeaterLiveMetadataTracker.clear();
        try {
            HttpRequestResponse exchange = requestResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");

            RepeaterLiveMetadataTracker.observe(
                    exchange,
                    new RepeaterMetadataFields.Metadata("expiring-tab", "expiring-group"),
                    1_000L);

            assertThat(RepeaterLiveMetadataTracker.resolveExchangeResolution(
                    exchange.request(),
                    exchange.response(),
                    1_000L + RepeaterLiveMetadataTracker.LIVE_METADATA_WINDOW_MS + 1).metadata().isPresent())
                    .isFalse();
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void observe_collapsesDuplicateMetadataForSameKey_withoutGrowingDeque() {
        RepeaterLiveMetadataTracker.clear();
        try {
            HttpRequestResponse exchange = requestResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            RepeaterMetadataFields.Metadata metadata =
                    new RepeaterMetadataFields.Metadata("same-tab", "same-group");

            RepeaterLiveMetadataTracker.observe(exchange, metadata, 1_000L);
            RepeaterLiveMetadataTracker.observe(exchange, metadata, 2_000L);

            assertThat(requestDequeFor(exchange.request())).hasSize(1);
            assertThat(exchangeDequeFor(exchange.request(), exchange.response())).hasSize(1);
            assertThat(RepeaterLiveMetadataTracker.resolveExchangeResolution(
                    exchange.request(),
                    exchange.response(),
                    2_500L).metadata())
                    .isEqualTo(metadata);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void observe_prunesStaleKeysDuringLaterLargeSetActivity() {
        RepeaterLiveMetadataTracker.clear();
        try {
            HttpRequestResponse staleExchange = requestResponse(
                    "GET /stale HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nS");
            HttpRequestResponse freshExchange = requestResponse(
                    "GET /fresh HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nF");

            RepeaterLiveMetadataTracker.observe(
                    staleExchange,
                    new RepeaterMetadataFields.Metadata("stale-tab", "stale-group"),
                    1_000L);
            RepeaterLiveMetadataTracker.observe(
                    freshExchange,
                    new RepeaterMetadataFields.Metadata("fresh-tab", "fresh-group"),
                    1_000L + RepeaterLiveMetadataTracker.LIVE_METADATA_WINDOW_MS
                            + RepeaterLiveMetadataTracker.GLOBAL_PRUNE_INTERVAL_MS
                            + 1);

            assertThat(requestIndex()).hasSize(1);
            assertThat(exchangeIndex()).hasSize(1);
            assertThat(RepeaterLiveMetadataTracker.resolveRequestResolution(
                    staleExchange.request(),
                    Long.MAX_VALUE).metadata().isPresent()).isFalse();
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void observe_capsPerKeyHistory_forLargerSameRequestSets() {
        RepeaterLiveMetadataTracker.clear();
        try {
            int maxEntriesPerKey = Reflect.getStaticInt(RepeaterLiveMetadataTracker.class, "MAX_ENTRIES_PER_KEY");
            HttpRequestResponse[] exchanges = new HttpRequestResponse[maxEntriesPerKey + 4];
            for (int i = 0; i < exchanges.length; i++) {
                exchanges[i] = requestResponse(
                        "GET /same HTTP/1.1\r\nHost: example.test\r\n\r\n",
                        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n" + i);
                RepeaterLiveMetadataTracker.observe(
                        exchanges[i],
                        new RepeaterMetadataFields.Metadata("tab-" + i, "group-" + i),
                        1_000L + i);
            }

            assertThat(requestDequeFor(exchanges[0].request())).hasSize(maxEntriesPerKey);
            HttpRequestResponse unseen = requestResponse(
                    "GET /same HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nunseen");
            assertThat(RepeaterLiveMetadataTracker.resolveRequestResolution(
                    unseen.request(),
                    2_000L).metadata().isPresent()).isFalse();
            assertThat(RepeaterLiveMetadataTracker.resolveExchangeResolution(
                    exchanges[exchanges.length - 1].request(),
                    exchanges[exchanges.length - 1].response(),
                    2_000L).metadata())
                    .isEqualTo(new RepeaterMetadataFields.Metadata(
                            "tab-" + (exchanges.length - 1),
                            "group-" + (exchanges.length - 1)));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    private static HttpRequestResponse requestResponse(String rawRequest, String rawResponse) {
        HttpRequest request = mock(HttpRequest.class);
        ByteArray requestBytes = byteArray(rawRequest);
        when(request.toByteArray()).thenReturn(requestBytes);

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(request);

        if (rawResponse != null) {
            HttpResponse response = mock(HttpResponse.class);
            ByteArray responseBytes = byteArray(rawResponse);
            when(response.toByteArray()).thenReturn(responseBytes);
            when(requestResponse.response()).thenReturn(response);
        }

        return requestResponse;
    }

    private static ByteArray byteArray(String value) {
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.getBytes()).thenReturn(value.getBytes(StandardCharsets.UTF_8));
        return bytes;
    }

    private static java.util.concurrent.ConcurrentHashMap<?, ?> requestIndex() {
        return getStaticConcurrentHashMap(RepeaterLiveMetadataTracker.class, "BY_REQUEST_HASH");
    }

    private static java.util.concurrent.ConcurrentHashMap<?, ?> exchangeIndex() {
        return getStaticConcurrentHashMap(RepeaterLiveMetadataTracker.class, "BY_EXCHANGE_HASH");
    }

    private static ConcurrentLinkedDeque<?> requestDequeFor(HttpRequest request) {
        return ConcurrentLinkedDeque.class.cast(requestIndex().get(requestHashFor(request)));
    }

    private static ConcurrentLinkedDeque<?> exchangeDequeFor(HttpRequest request, HttpResponse response) {
        return ConcurrentLinkedDeque.class.cast(exchangeIndex().get(exchangeHashFor(request, response)));
    }

    private static String requestHashFor(HttpRequest request) {
        return (String) ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic(
                RepeaterLiveMetadataTracker.class,
                "requestHash",
                request);
    }

    private static String exchangeHashFor(HttpRequest request, HttpResponse response) {
        return (String) ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic(
                RepeaterLiveMetadataTracker.class,
                "exchangeHash",
                request,
                response);
    }
}
