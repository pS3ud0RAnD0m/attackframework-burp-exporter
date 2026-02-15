package ai.attackframework.tools.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import ai.attackframework.tools.burp.sinks.OpenSearchTrafficHandler;
import ai.attackframework.tools.burp.sinks.ToolIndexStatsReporter;
import ai.attackframework.tools.burp.ui.AttackFrameworkPanel;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.Version;

public class Exporter implements BurpExtension {
    /**
     * Registers the extension with Burp, wiring logging and UI composition.
     *
     * <p>Caller must invoke on Burp's initialization thread. UI components are created on the EDT
     * when {@link ai.attackframework.tools.burp.ui.AttackFrameworkPanel} is instantiated.</p>
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

            api.userInterface().registerSuiteTab(tabTitle, new AttackFrameworkPanel());
            api.http().registerHttpHandler(new OpenSearchTrafficHandler());
            ToolIndexStatsReporter.start();

            Logger.logInfo("Burp Exporter v" + version + " initialized successfully.");
        } catch (Exception e) {
            Logger.logError("Burp Exporter " + version + " initialization failed: " + e.getMessage(), e);
        }
    }
}
