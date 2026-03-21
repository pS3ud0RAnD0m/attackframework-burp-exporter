package ai.attackframework.tools.burp;

import java.lang.reflect.InvocationTargetException;

import javax.swing.SwingUtilities;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.sinks.OpenSearchTrafficHandler;
import ai.attackframework.tools.burp.sinks.ToolIndexLogForwarder;
import ai.attackframework.tools.burp.ui.AttackFrameworkPanel;
import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.Version;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

public class Exporter implements BurpExtension {
    private volatile Registration unloadRegistration;
    private volatile Registration suiteTabRegistration;
    private volatile Registration httpHandlerRegistration;
    private volatile ToolIndexLogForwarder logForwarder;

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
            logForwarder = new ToolIndexLogForwarder();
            Logger.registerListener(logForwarder);
            BatchSizeController.getInstance().setOnChangeListener(size -> Logger.logDebug("Batch size: " + size));

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

            httpHandlerRegistration = api.http().registerHttpHandler(new OpenSearchTrafficHandler());

            Logger.logInfo("Burp Exporter v" + version + " initialized successfully.");
        } catch (RuntimeException e) {
            Logger.logError("Burp Exporter v" + version + " initialization failed: " + e.getMessage(), e);
            cleanupExtensionState();
        }
    }

    private void cleanupExtensionState() {
        ToolIndexLogForwarder forwarder = logForwarder;
        if (forwarder != null) {
            Logger.unregisterListener(forwarder);
            forwarder.stop();
            logForwarder = null;
        }

        safeDeregister(httpHandlerRegistration);
        httpHandlerRegistration = null;
        safeDeregister(suiteTabRegistration);
        suiteTabRegistration = null;

        BatchSizeController.getInstance().setOnChangeListener(null);
        ExportReporterLifecycle.stopAndClearSessionState();
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
