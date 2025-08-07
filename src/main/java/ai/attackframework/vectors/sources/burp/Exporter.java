package ai.attackframework.vectors.sources.burp;

import ai.attackframework.vectors.sources.burp.ui.ExporterTab;
import ai.attackframework.vectors.sources.burp.utils.Logger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Exporter implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        try {
            api.extension().setName("Attack Framework: Burp Exporter");

            Logger.initialize(api.logging());

            api.userInterface().registerSuiteTab("Attack Framework", new ExporterTab());

            Logger.logInfo("Initialized successfully.");
        } catch (Exception e) {
            Logger.logError("Initialization failed: " + e.getMessage());
        }
    }
}
