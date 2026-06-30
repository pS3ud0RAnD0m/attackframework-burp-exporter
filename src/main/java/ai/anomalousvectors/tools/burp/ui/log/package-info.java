/**
 * UI-internal logging components used by {@link ai.anomalousvectors.tools.burp.ui.LogPanel}.
 *
 * <p>{@link ai.anomalousvectors.tools.burp.ui.log.LogStore} holds a bounded in-memory log model,
 * and {@link ai.anomalousvectors.tools.burp.ui.log.LogRenderer} renders entries into the panel's
 * {@code JTextPane}. These types are EDT-aware: rendering occurs on the EDT; callers must avoid
 * mutating Swing state off the EDT.</p>
 */
package ai.anomalousvectors.tools.burp.ui.log;
