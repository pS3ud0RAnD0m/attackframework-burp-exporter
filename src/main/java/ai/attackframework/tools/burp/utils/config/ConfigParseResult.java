package ai.attackframework.tools.burp.utils.config;

/**
 * Outcome of parsing and mapping imported configuration JSON.
 *
 * @param state normalized settings applied to the UI
 * @param report non-fatal warnings for unrecognized keys and values
 */
public record ConfigParseResult(ConfigState.State state, ConfigImportReport report) { }