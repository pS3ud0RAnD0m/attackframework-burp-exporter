/**
 * Common utilities shared across the extension.
 *
 * <p>Includes logging ({@link ai.anomalousvectors.tools.burp.utils.Logger}), export pressure log
 * throttling ({@link ai.anomalousvectors.tools.burp.utils.ExportPressureLogThrottler}), version
 * accessors, filesystem helpers, regex helpers, and small helpers reused by UI and sinks. These
 * classes are UI-agnostic; callers may use them from background threads as needed.</p>
 */
package ai.anomalousvectors.tools.burp.utils;
