package ai.attackframework.tools.burp;

import java.lang.reflect.InvocationTargetException;

import javax.swing.SwingUtilities;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.sinks.ExporterIndexLogForwarder;
import ai.attackframework.tools.burp.sinks.TrafficHttpHandler;
import ai.attackframework.tools.burp.sinks.RepeaterHistoryIndexReporter;
import ai.attackframework.tools.burp.ui.AttackFrameworkPanel;
import ai.attackframework.tools.burp.ui.ConfigPanel;
import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.Version;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

/**
 * Burp extension entry point for the exporter.
 *
 * <p>This type wires lifecycle hooks, logging, runtime metadata, and the suite-tab UI. Swing UI
 * registration is delegated to the EDT during {@link #initialize(MontoyaApi)} when Burp invokes
 * startup from a background thread.</p>
 */
public class Exporter implements BurpExtension {
    private volatile Registration unloadRegistration;
    private volatile Registration suiteTabRegistration;
    private volatile Registration httpHandlerRegistration;
    private volatile Registration requestEditorRegistration;
    private volatile Registration responseEditorRegistration;
    private volatile Registration contextMenuRegistration;
    private volatile ExporterIndexLogForwarder logForwarder;

    /**
     * Registers the extension with Burp, wiring logging and UI composition.
     *
     * <p>Suite tab UI is created on the EDT so Swing components are never built on a
     * background thread (Burp may call {@code initialize} from a non-EDT thread when
     * the extension is loaded at startup). Log panel message delivery is handled by
     * {@link ai.attackframework.tools.burp.ui.LogPanel} addNotify/removeNotify and
     * {@link ai.attackframework.tools.burp.utils.Logger} replay buffer.</p>
     *
     * @param api Montoya API handle provided by Burp
     */
    @Override
    public void initialize(MontoyaApi api) {
        final String extensionName = "Attack Framework: Burp Exporter";
        final String tabTitle = "Attack Framework";
        String version = Version.get();

        try {
            api.extension().setName(extensionName);
            unloadRegistration = api.extension().registerUnloadingHandler(this::cleanupExtensionState);

            MontoyaApiProvider.set(api);
            BurpRuntimeMetadata.prime(api);
            Logger.initialize(api.logging());
            logForwarder = new ExporterIndexLogForwarder();
            Logger.registerListener(logForwarder);
            BatchSizeController.getInstance().setOnChangeListener(size -> Logger.logDebug("Batch size: " + size));
            requestEditorRegistration = api.userInterface().registerHttpRequestEditorProvider(
                    RepeaterHistoryIndexReporter.requestEditorProvider());
            responseEditorRegistration = api.userInterface().registerHttpResponseEditorProvider(
                    RepeaterHistoryIndexReporter.responseEditorProvider());
            contextMenuRegistration = api.userInterface().registerContextMenuItemsProvider(
                    RepeaterHistoryIndexReporter.contextMenuItemsProvider());

            if (SwingUtilities.isEventDispatchThread()) {
                registerUi(api, tabTitle);
            } else {
                try {
                    SwingUtilities.invokeAndWait(() -> registerUi(api, tabTitle));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Extension UI registration interrupted", e);
                } catch (InvocationTargetException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof RuntimeException re) throw re;
                    if (cause instanceof Error err) throw err;
                    throw new RuntimeException(cause != null ? cause : e);
                }
            }

            httpHandlerRegistration = api.http().registerHttpHandler(new TrafficHttpHandler());

            Logger.logInfo("Burp Exporter v" + version + " initialized successfully.");
        } catch (RuntimeException e) {
            Logger.logError("Burp Exporter v" + version + " initialization failed: " + e.getMessage(), e);
            cleanupExtensionState();
        }
    }

    private void cleanupExtensionState() {
        ExporterIndexLogForwarder forwarder = logForwarder;
        if (forwarder != null) {
            Logger.unregisterListener(forwarder);
            forwarder.stop();
            logForwarder = null;
        }

        safeDeregister(httpHandlerRegistration);
        httpHandlerRegistration = null;
        safeDeregister(requestEditorRegistration);
        requestEditorRegistration = null;
        safeDeregister(responseEditorRegistration);
        responseEditorRegistration = null;
        safeDeregister(contextMenuRegistration);
        contextMenuRegistration = null;
        safeDeregister(suiteTabRegistration);
        suiteTabRegistration = null;

        BatchSizeController.getInstance().setOnChangeListener(null);
        ExportReporterLifecycle.stopAndClearSessionState();
        // Unload is the last chance to release pooled connections, TLS session caches, and the
        // HTTP/2 reactor/scheduler threads owned by the cached OpenSearch transports. Run
        // synchronously here so the classloader can be GC'd cleanly; closeAll() is idempotent
        // if a Stop-triggered async closeAll() already ran.
        OpenSearchConnector.closeAll();
        ConfigPanel.shutdownStartupExecutor();
        Logger.resetState();

        safeDeregister(unloadRegistration);
        unloadRegistration = null;
    }

    private void registerUi(MontoyaApi api, String tabTitle) {
        suiteTabRegistration = api.userInterface().registerSuiteTab(tabTitle, new AttackFrameworkPanel());
    }

    private static void safeDeregister(Registration registration) {
        if (registration == null) {
            return;
        }
        try {
            registration.deregister();
        } catch (RuntimeException ignored) {
            // Burp may already be tearing the object down during unload.
        }
    }
}
