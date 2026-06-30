package ai.anomalousvectors.tools.burp.sinks;

import java.lang.ref.WeakReference;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Tracks short-lived best-effort Repeater tab/group metadata for live traffic correlation.
 *
 * <p>The hidden Repeater editor providers observe Burp rebinding request/response pairs into
 * visible Repeater tabs. This tracker stores recent tab/group metadata keyed first by the observed
 * {@link HttpRequest} object identity, then by request bytes and, when available, by
 * request+response bytes. Live traffic export can then correlate Repeater-origin traffic without
 * guessing from whatever tab happens to be focused later. Some Burp paths appear to clone or
 * rebuild requests before they reach the live handler, so identical concurrent tabs can still end
 * up unresolved and intentionally export empty metadata.</p>
 */
final class RepeaterLiveMetadataTracker {

    static final long LIVE_METADATA_WINDOW_MS = 30_000L;
    static final long GLOBAL_PRUNE_INTERVAL_MS = 5_000L;
    private static final int MAX_ENTRIES_PER_KEY = 8;

    /**
     * Buckets recent observed requests by {@link System#identityHashCode(Object)}.
     *
     * <p>The deque still stores the original request reference and resolution rechecks
     * {@code observed.request() == request}, so rare hash collisions only share a bucket and do not
     * cause false-positive matches.</p>
     */
    private static final ConcurrentHashMap<Integer, ConcurrentLinkedDeque<ObservedRequestIdentity>> BY_REQUEST_IDENTITY =
            new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, ConcurrentLinkedDeque<ObservedMetadata>> BY_REQUEST_HASH =
            new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, ConcurrentLinkedDeque<ObservedMetadata>> BY_EXCHANGE_HASH =
            new ConcurrentHashMap<>();
    private static final AtomicLong LAST_GLOBAL_PRUNE_AT_MS = new AtomicLong(0L);

    private RepeaterLiveMetadataTracker() {}

    /**
     * Clears all live Repeater correlation state.
     *
     * <p>Tests and exporter lifecycle transitions call this before a new run so stale editor
     * observations cannot leak into later live traffic resolution.</p>
     */
    static void clear() {
        BY_REQUEST_IDENTITY.clear();
        BY_REQUEST_HASH.clear();
        BY_EXCHANGE_HASH.clear();
        LAST_GLOBAL_PRUNE_AT_MS.set(0L);
    }

    /**
     * Records a recent Repeater editor observation for later live traffic correlation.
     *
     * <p>The caller may invoke this from any thread. Only present metadata is stored. Resolution
     * later prefers the exact {@link HttpRequest} object identity, then falls back to byte hashes
     * when Burp does not preserve the original request object.</p>
     */
    static void observe(HttpRequestResponse requestResponse, RepeaterMetadataFields.Metadata metadata) {
        observe(requestResponse, metadata, System.currentTimeMillis());
    }

    /**
     * Records a recent Repeater editor observation for later live traffic correlation.
     *
     * @param requestResponse observed request/response pair from a Repeater editor callback
     * @param metadata best-effort Repeater tab/group metadata for that editor state
     * @param nowMs observation time in epoch milliseconds
     */
    static void observe(HttpRequestResponse requestResponse, RepeaterMetadataFields.Metadata metadata, long nowMs) {
        if (requestResponse == null || metadata == null || !metadata.isPresent()) {
            return;
        }
        pruneIndexesIfDue(nowMs);
        HttpRequest request = requestResponse.request();
        if (request != null) {
            addByRequestIdentity(request, metadata, nowMs);
        }
        String requestHash = requestHash(requestResponse.request());
        if (requestHash != null) {
            add(BY_REQUEST_HASH, requestHash, metadata, nowMs);
        }
        String exchangeHash = exchangeHash(requestResponse.request(), requestResponse.response());
        if (exchangeHash != null) {
            add(BY_EXCHANGE_HASH, exchangeHash, metadata, nowMs);
        }
    }

    /**
     * Resolves best-effort metadata for a live Repeater request.
     *
     * <p>The result is empty when there is no confident match and ambiguous when multiple distinct
     * recent editor observations share the same request bytes.</p>
     */
    static Resolution resolveRequestResolution(HttpRequest request) {
        return resolveRequestResolution(request, System.currentTimeMillis());
    }

    /**
     * Resolves best-effort metadata for a live Repeater request.
     *
     * @param request live request being exported
     * @param nowMs resolution time in epoch milliseconds
     * @return a present, empty, or ambiguous resolution for the current request
     */
    static Resolution resolveRequestResolution(HttpRequest request, long nowMs) {
        pruneIndexesIfDue(nowMs);
        Resolution identityResolution = resolveByRequestIdentity(request, nowMs);
        if (identityResolution.metadata().isPresent() || identityResolution.ambiguous()) {
            return identityResolution;
        }
        return resolve(
                BY_REQUEST_HASH,
                requestHash(request),
                nowMs,
                RepeaterMetadataTraceLabels.REQUEST_HASH);
    }

    /**
     * Resolves best-effort metadata for a live Repeater request/response pair.
     *
     * <p>Exchange correlation is stricter than request-only correlation because it requires both
     * request and response bytes to match a recent editor observation.</p>
     */
    static Resolution resolveExchangeResolution(HttpRequest request, HttpResponse response) {
        return resolveExchangeResolution(request, response, System.currentTimeMillis());
    }

    /**
     * Resolves best-effort metadata for a live Repeater request/response pair.
     *
     * @param request live request being exported
     * @param response live response being exported
     * @param nowMs resolution time in epoch milliseconds
     * @return a present, empty, or ambiguous resolution for the current exchange
     */
    static Resolution resolveExchangeResolution(HttpRequest request, HttpResponse response, long nowMs) {
        pruneIndexesIfDue(nowMs);
        return resolve(
                BY_EXCHANGE_HASH,
                exchangeHash(request, response),
                nowMs,
                RepeaterMetadataTraceLabels.EXCHANGE_HASH);
    }

    private static void add(
            ConcurrentHashMap<String, ConcurrentLinkedDeque<ObservedMetadata>> index,
            String key,
            RepeaterMetadataFields.Metadata metadata,
            long nowMs) {
        if (key == null || metadata == null || !metadata.isPresent()) {
            return;
        }
        ConcurrentLinkedDeque<ObservedMetadata> deque =
                index.computeIfAbsent(key, ignored -> new ConcurrentLinkedDeque<>());
        pruneDeque(deque, nowMs);
        ObservedMetadata last = deque.peekLast();
        if (last != null && metadata.equals(last.metadata())) {
            deque.pollLast();
        }
        deque.addLast(new ObservedMetadata(metadata, nowMs));
        while (deque.size() > MAX_ENTRIES_PER_KEY) {
            deque.pollFirst();
        }
    }

    private static void addByRequestIdentity(
            HttpRequest request,
            RepeaterMetadataFields.Metadata metadata,
            long nowMs) {
        if (request == null || metadata == null || !metadata.isPresent()) {
            return;
        }
        int key = System.identityHashCode(request);
        ConcurrentLinkedDeque<ObservedRequestIdentity> deque =
                BY_REQUEST_IDENTITY.computeIfAbsent(key, ignored -> new ConcurrentLinkedDeque<>());
        pruneIdentityDeque(deque, nowMs);
        ObservedRequestIdentity last = deque.peekLast();
        if (last != null
                && last.request() == request
                && metadata.equals(last.metadata())) {
            deque.pollLast();
        }
        deque.addLast(new ObservedRequestIdentity(new WeakReference<>(request), metadata, nowMs));
        while (deque.size() > MAX_ENTRIES_PER_KEY) {
            deque.pollFirst();
        }
    }

    private static Resolution resolve(
            ConcurrentHashMap<String, ConcurrentLinkedDeque<ObservedMetadata>> index,
            String key,
            long nowMs,
            String sourceLabel) {
        if (key == null) {
            return Resolution.empty();
        }
        ConcurrentLinkedDeque<ObservedMetadata> deque = index.get(key);
        if (deque == null) {
            return Resolution.empty();
        }
        pruneDeque(deque, nowMs);
        if (deque.isEmpty()) {
            index.remove(key, deque);
            return Resolution.empty();
        }
        Set<RepeaterMetadataFields.Metadata> distinct = new HashSet<>();
        for (ObservedMetadata observed : deque) {
            if (observed != null && observed.metadata() != null && observed.metadata().isPresent()) {
                distinct.add(observed.metadata());
                if (distinct.size() > 1) {
                    return Resolution.ambiguousResolution(sourceLabel);
                }
            }
        }
        return distinct.isEmpty()
                ? Resolution.empty()
                : Resolution.present(distinct.iterator().next(), sourceLabel);
    }

    private static Resolution resolveByRequestIdentity(HttpRequest request, long nowMs) {
        if (request == null) {
            return Resolution.empty();
        }
        int key = System.identityHashCode(request);
        ConcurrentLinkedDeque<ObservedRequestIdentity> deque = BY_REQUEST_IDENTITY.get(key);
        if (deque == null) {
            return Resolution.empty();
        }
        pruneIdentityDeque(deque, nowMs);
        if (deque.isEmpty()) {
            BY_REQUEST_IDENTITY.remove(key, deque);
            return Resolution.empty();
        }
        Set<RepeaterMetadataFields.Metadata> distinct = new HashSet<>();
        for (ObservedRequestIdentity observed : deque) {
            if (observed == null || observed.request() != request) {
                continue;
            }
            RepeaterMetadataFields.Metadata metadata = observed.metadata();
            if (metadata != null && metadata.isPresent()) {
                distinct.add(metadata);
                if (distinct.size() > 1) {
                    return Resolution.ambiguousResolution(RepeaterMetadataTraceLabels.REQUEST_IDENTITY);
                }
            }
        }
        return distinct.isEmpty()
                ? Resolution.empty()
                : Resolution.present(
                        distinct.iterator().next(),
                        RepeaterMetadataTraceLabels.REQUEST_IDENTITY);
    }

    private static void pruneDeque(ConcurrentLinkedDeque<ObservedMetadata> deque, long nowMs) {
        if (deque == null) {
            return;
        }
        while (true) {
            ObservedMetadata first = deque.peekFirst();
            if (first == null || nowMs - first.observedAtMs() <= LIVE_METADATA_WINDOW_MS) {
                return;
            }
            deque.pollFirst();
        }
    }

    private static void pruneIdentityDeque(ConcurrentLinkedDeque<ObservedRequestIdentity> deque, long nowMs) {
        if (deque == null) {
            return;
        }
        while (true) {
            ObservedRequestIdentity first = deque.peekFirst();
            if (first == null) {
                return;
            }
            if (first.request() != null && nowMs - first.observedAtMs() <= LIVE_METADATA_WINDOW_MS) {
                return;
            }
            deque.pollFirst();
        }
    }

    private static void pruneIndexesIfDue(long nowMs) {
        long lastPruneAtMs = LAST_GLOBAL_PRUNE_AT_MS.get();
        if (nowMs - lastPruneAtMs < GLOBAL_PRUNE_INTERVAL_MS) {
            return;
        }
        if (!LAST_GLOBAL_PRUNE_AT_MS.compareAndSet(lastPruneAtMs, nowMs)) {
            return;
        }
        pruneIdentityIndex(nowMs);
        pruneIndex(BY_REQUEST_HASH, nowMs);
        pruneIndex(BY_EXCHANGE_HASH, nowMs);
    }

    private static void pruneIdentityIndex(long nowMs) {
        if (BY_REQUEST_IDENTITY.isEmpty()) {
            return;
        }
        for (var entry : BY_REQUEST_IDENTITY.entrySet()) {
            ConcurrentLinkedDeque<ObservedRequestIdentity> deque = entry.getValue();
            pruneIdentityDeque(deque, nowMs);
            if (deque == null || deque.isEmpty()) {
                BY_REQUEST_IDENTITY.remove(entry.getKey(), deque);
            }
        }
    }

    private static void pruneIndex(
            ConcurrentHashMap<String, ConcurrentLinkedDeque<ObservedMetadata>> index,
            long nowMs) {
        if (index == null || index.isEmpty()) {
            return;
        }
        for (var entry : index.entrySet()) {
            ConcurrentLinkedDeque<ObservedMetadata> deque = entry.getValue();
            pruneDeque(deque, nowMs);
            if (deque == null || deque.isEmpty()) {
                index.remove(entry.getKey(), deque);
            }
        }
    }

    private static String requestHash(HttpRequest request) {
        if (request == null) {
            return null;
        }
        return sha256(List.of(request.toByteArray().getBytes()));
    }

    private static String exchangeHash(HttpRequest request, HttpResponse response) {
        if (request == null || response == null) {
            return null;
        }
        return sha256(List.of(request.toByteArray().getBytes(), response.toByteArray().getBytes()));
    }

    private static String sha256(List<byte[]> parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            if (parts != null) {
                for (byte[] part : parts) {
                    if (part != null && part.length > 0) {
                        digest.update(part);
                    }
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest unavailable", e);
        }
    }

    private record ObservedMetadata(
            RepeaterMetadataFields.Metadata metadata,
            long observedAtMs) {}

    private record ObservedRequestIdentity(
            WeakReference<HttpRequest> requestRef,
            RepeaterMetadataFields.Metadata metadata,
            long observedAtMs) {
        private HttpRequest request() {
            return requestRef == null ? null : requestRef.get();
        }
    }

    /**
     * Resolution outcome for live Repeater metadata lookup.
     *
     * <p>{@code metadata()} is only populated when the tracker found exactly one confident match.
     * {@code ambiguous()} signals that multiple distinct recent candidates matched and callers
     * should prefer null/empty metadata instead of guessing from current UI focus. The
     * {@code sourceLabel()} field identifies which tracker path produced the decision so trace logs
     * can explain whether the match came from exact request identity, request bytes, or
     * request+response bytes.</p>
     */
    static record Resolution(
            RepeaterMetadataFields.Metadata metadata,
            boolean ambiguous,
            String sourceLabel) {
        Resolution {
            metadata = metadata == null ? RepeaterMetadataFields.Metadata.empty() : metadata;
            sourceLabel = normalizeSourceLabel(sourceLabel);
        }

        private static Resolution empty() {
            return new Resolution(
                    RepeaterMetadataFields.Metadata.empty(),
                    false,
                    RepeaterMetadataTraceLabels.NONE);
        }

        private static Resolution present(
                RepeaterMetadataFields.Metadata metadata,
                String sourceLabel) {
            return new Resolution(metadata, false, sourceLabel);
        }

        private static Resolution ambiguousResolution(String sourceLabel) {
            return new Resolution(RepeaterMetadataFields.Metadata.empty(), true, sourceLabel);
        }

        private static String normalizeSourceLabel(String sourceLabel) {
            return sourceLabel == null || sourceLabel.isBlank()
                    ? RepeaterMetadataTraceLabels.NONE
                    : sourceLabel.trim();
        }
    }
}
