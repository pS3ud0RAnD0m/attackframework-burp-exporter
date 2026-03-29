package ai.attackframework.tools.burp.utils.opensearch;

import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.config.SecureCredentialStore;
import ai.attackframework.tools.burp.utils.Logger;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that {@link OpenSearchClientWrapper#testConnection(String)} emits log events
 * to the {@link Logger} listener bus so {@code LogPanel} can display connection attempts.
 * For client-side failures (no HTTP exchanged), only the error is logged — no reconstructed request/response.
 */
class OpenSearchClientWrapperLoggingTest {

    private final List<LoggerEvent> events = new CopyOnWriteArrayList<>();
    private final CountDownLatch latch = new CountDownLatch(1);
    private final Logger.LogListener listener = (level, message) -> {
        events.add(new LoggerEvent(level, message));
        latch.countDown();
    };

    private void cleanUp() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        SecureCredentialStore.clearAll();
        RuntimeConfig.updateState(null);
        events.clear();
        while (latch.getCount() > 0) {
            latch.countDown();
        }
    }

    @Test
    void testConnection_withInvalidUrl_emitsLogEvent() throws Exception {
        Logger.resetState();
        Logger.registerListener(listener);
        try {
            // Run on EDT so Logger listener is invoked synchronously (Logger dispatches to EDT when off it).
            SwingUtilities.invokeAndWait(() ->
                    OpenSearchClientWrapper.testConnection("http://127.0.0.1:1"));

            // Client-side failure (connection refused): we log the error only, no fake request/response.
            assertThat(events)
                    .anySatisfy(e -> {
                        assertThat(e.level()).isNotEmpty();
                        assertThat(e.message()).contains("[OpenSearch]").contains("Connection failed");
                    });
            assertThat(events).noneMatch(e -> e.message().contains("Request:"));
        } finally {
            cleanUp();
        }
    }

    @Test
    void testConnection_withPinnedModeButNoImportedCertificate_emitsTlsLogEvents() throws Exception {
        String originalInsecure = System.getProperty("OPENSEARCH_INSECURE");
        Logger.resetState();
        SecureCredentialStore.clearAll();
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, false,
                        true, ConfigState.DEFAULT_FILE_TOTAL_CAP_BYTES,
                        true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        true, "https://opensearch.url:9200", "", "", ConfigState.OPEN_SEARCH_TLS_PINNED),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        ));
        System.clearProperty("OPENSEARCH_INSECURE");
        Logger.registerListener(listener);
        try {
            SwingUtilities.invokeAndWait(() ->
                    OpenSearchClientWrapper.testConnection("https://opensearch.url:9200"));

            assertThat(events).anySatisfy(e -> assertThat(e.message())
                    .contains("Testing connection: url=https://opensearch.url:9200")
                    .contains("tlsMode=pinned")
                    .contains("pinnedCertificateLoaded=false"));
            assertThat(events).anySatisfy(e -> assertThat(e.message())
                    .contains("TLS mode requires a pinned certificate, but none is imported"));
            assertThat(events).anySatisfy(e -> assertThat(e.message())
                    .contains("Connection failed for https://opensearch.url:9200")
                    .contains("trust=Pinned certificate not imported"));
        } finally {
            if (originalInsecure == null) {
                System.clearProperty("OPENSEARCH_INSECURE");
            } else {
                System.setProperty("OPENSEARCH_INSECURE", originalInsecure);
            }
            cleanUp();
        }
    }

    private record LoggerEvent(String level, String message) {
        LoggerEvent {
            level = level == null ? "" : level;
            message = message == null ? "" : message;
        }
    }
}
