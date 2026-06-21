package ai.attackframework.tools.burp.testutils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.LockSupport;

import ai.attackframework.tools.burp.utils.concurrent.SnapshotFlushExecutor;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

/** Shared helpers for {@link ai.attackframework.tools.burp.utils.concurrent.SnapshotExportEngine} tests. */
public final class SnapshotExportEngineTestSupport {

    private SnapshotExportEngineTestSupport() {}

    /**
     * Returns a file-only runtime state that routes snapshot flushes through {@code FileExportService}.
     */
    public static ConfigState.State fileOnlyTrafficState(Path root) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        true,
                        root.toString(),
                        true,
                        false,
                        false,
                        "",
                        "",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy_history"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }

    /**
     * Builds a minimal prepared traffic document with an explicit bulk-byte estimate for chunk tests.
     */
    public static PreparedExportDocument preparedTrafficDoc(String indexName, int sequence, long estimatedBytes) {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("sequence", sequence);
        document.put("request", Map.of("url", "https://example.test/item/" + sequence));
        byte[] ndjson = ("{\"index\":{}}\n{\"sequence\":" + sequence + "}\n").getBytes(StandardCharsets.UTF_8);
        return new PreparedExportDocument(indexName, "traffic", document, estimatedBytes, ndjson);
    }

    /**
     * Polls until both snapshot flush pools report zero active workers or the deadline passes.
     *
     * @return {@code true} when both pools are idle
     */
    public static boolean awaitFlushPoolsIdle(long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            SnapshotFlushExecutor.Snapshot stats = SnapshotFlushExecutor.stats();
            if (stats.flush().activeCount() == 0 && stats.dualSink().activeCount() == 0) {
                return true;
            }
            LockSupport.parkNanos(50_000_000L);
        }
        SnapshotFlushExecutor.Snapshot stats = SnapshotFlushExecutor.stats();
        return stats.flush().activeCount() == 0 && stats.dualSink().activeCount() == 0;
    }
}
