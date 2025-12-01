/**
 * Action controller layer for the configuration UI.
 *
 * <p>{@link ai.attackframework.tools.burp.ui.controller.ConfigController} coordinates
 * long-running work (file I/O, OpenSearch operations, configuration import/export)
 * on background threads and reports results back to the Swing UI through the
 * {@link ai.attackframework.tools.burp.ui.controller.ConfigController.Ui} callback
 * surface. The controller deliberately avoids touching Swing components directly;
 * callers are responsible for updating widgets on the EDT.</p>
 */
package ai.attackframework.tools.burp.ui.controller;
