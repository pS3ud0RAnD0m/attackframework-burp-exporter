/**
 * Action controller layer for the configuration UI.
 *
 * <p>{@link ai.anomalousvectors.tools.burp.ui.controller.ConfigController} coordinates
 * long-running work (file I/O, OpenSearch operations, configuration import/export)
 * on background threads and reports results back to the Swing UI through the
 * {@link ai.anomalousvectors.tools.burp.ui.controller.ConfigController.Ui} callback
 * surface. The controller deliberately avoids touching Swing components directly;
 * callers are responsible for updating widgets on the EDT. The controller is
 * thread-aware but not Swing-aware; invoke it from background threads when
 * performing I/O.</p>
 */
package ai.anomalousvectors.tools.burp.ui.controller;
