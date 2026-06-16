package ai.attackframework.tools.burp.sinks;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-export-run set of stable item keys already exported during backlog or periodic polls.
 *
 * <p>Periodic sitemap/findings polls skip known keys without building documents. Cleared on
 * reporter {@code stop()}.</p>
 */
final class PeriodicExportSeenKeys {

    private final Set<String> seenKeys = ConcurrentHashMap.newKeySet();

    void recordSeen(String itemKey) {
        if (itemKey == null || itemKey.isBlank()) {
            return;
        }
        seenKeys.add(itemKey);
    }

    boolean isNew(String itemKey) {
        if (itemKey == null || itemKey.isBlank()) {
            return false;
        }
        return !seenKeys.contains(itemKey);
    }

    boolean claimNew(String itemKey) {
        if (itemKey == null || itemKey.isBlank()) {
            return false;
        }
        return seenKeys.add(itemKey);
    }

    void clear() {
        seenKeys.clear();
    }

    int trackedCount() {
        return seenKeys.size();
    }
}
