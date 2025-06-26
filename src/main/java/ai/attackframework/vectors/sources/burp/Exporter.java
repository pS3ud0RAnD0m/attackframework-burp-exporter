package ai.attackframework.vectors.sources.burp;

import ai.attackframework.vectors.sources.burp.ui.AttackVectorsTab;
import ai.attackframework.vectors.sources.burp.utils.Logger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Exporter implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        try {
            api.extension().setName("Attack Vectors: Burp Exporter");

            Logger.initialize(api.logging());

            api.userInterface().registerSuiteTab("Attack Vectors", new AttackVectorsTab());

            api.logging().logToOutput("'Attack Vectors: Burp Exporter' initialized successfully.");
        } catch (Exception e) {
            api.logging().logToError("Initialization failed: " + e.getMessage());
        }
    }
}
