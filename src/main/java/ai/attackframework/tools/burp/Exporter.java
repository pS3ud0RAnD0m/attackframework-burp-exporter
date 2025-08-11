package ai.attackframework.tools.burp;

import ai.attackframework.tools.burp.ui.AttackFrameworkPanel;
import ai.attackframework.tools.burp.utils.Logger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Exporter implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        try {
            api.extension().setName("Attack Framework: Burp Exporter");

            Logger.initialize(api.logging());

            api.userInterface().registerSuiteTab("Attack Framework", new AttackFrameworkPanel());

            Logger.logInfo("Initialized successfully.");
        } catch (Exception e) {
            Logger.logError("Initialization failed: " + e.getMessage());
        }
    }
}
