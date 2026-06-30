package ai.anomalousvectors.tools.burp.utils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Utilities for copying and nesting string-keyed {@link Map} instances used across export code.
 */
public final class StringKeyedMaps {

    private StringKeyedMaps() { }

    /** Returns a defensive copy retaining only {@link String} keys. */
    public static Map<String, Object> copy(Map<?, ?> source) {
        Map<String, Object> copy = new LinkedHashMap<>();
        if (source == null) {
            return copy;
        }
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() instanceof String key) {
                copy.put(key, entry.getValue());
            }
        }
        return copy;
    }

    /**
     * Returns the nested map at {@code key}, copying an existing map in place or creating one with
     * {@code initializer} when absent.
     */
    public static Map<String, Object> nested(
            Map<String, Object> parent,
            String key,
            Supplier<Map<String, Object>> initializer) {
        Object existing = parent.get(key);
        if (existing instanceof Map<?, ?> existingMap) {
            Map<String, Object> copy = copy(existingMap);
            parent.put(key, copy);
            return copy;
        }
        Map<String, Object> fresh = initializer.get();
        parent.put(key, fresh);
        return fresh;
    }
}
