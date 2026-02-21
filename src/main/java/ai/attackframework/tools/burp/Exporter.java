package ai.attackframework.tools.burp;

import java.lang.reflect.InvocationTargetException;

import javax.swing.SwingUtilities;

import ai.attackframework.tools.burp.sinks.OpenSearchTrafficHandler;
import ai.attackframework.tools.burp.sinks.ToolIndexStatsReporter;
import ai.attackframework.tools.burp.ui.AttackFrameworkPanel;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.Version;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Exporter implements BurpExtension {
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

            Logger.initialize(api.logging());

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

            api.http().registerHttpHandler(new OpenSearchTrafficHandler());
            ToolIndexStatsReporter.start();

            Logger.logInfo("Burp Exporter v" + version + " initialized successfully.");
        } catch (Exception e) {
            Logger.logError("Burp Exporter v" + version + " initialization failed: " + e.getMessage(), e);
        }
    }

    private static void registerUi(MontoyaApi api, String tabTitle) {
        api.userInterface().registerSuiteTab(tabTitle, new AttackFrameworkPanel());
    }
}
