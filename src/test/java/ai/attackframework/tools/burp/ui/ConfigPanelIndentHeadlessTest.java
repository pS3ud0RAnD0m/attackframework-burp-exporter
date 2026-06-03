package ai.attackframework.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.ui.primitives.TriStateCheckBox;

class ConfigPanelIndentHeadlessTest {

    @Test
    void sourcesSubOptions_useWiderChildIndent() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JButton trafficExpand = findByName(panel, "src.traffic.expand", JButton.class);
        JCheckBox traffic = findByName(panel, "src.traffic", JCheckBox.class);
        JCheckBox proxyHistory = findByName(panel, "src.traffic.proxy_history", JCheckBox.class);

        runEdt(() -> {
            trafficExpand.doClick();
            layoutTree(panel);

            assertThat(absoluteX(proxyHistory, panel) - absoluteX(traffic, panel)).isGreaterThanOrEqualTo(55);
        });
    }

    @Test
    void fieldNestedChildren_useWiderChildIndent_withoutChangingTopSectionIndent() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JButton trafficExpand = findByName(panel, "fields.traffic.expand", JButton.class);
        JButton burpExpand = findByName(panel, "fields.traffic.section.burp.expand", JButton.class);
        TriStateCheckBox burp = findByName(panel, "fields.traffic.section.burp", TriStateCheckBox.class);
        TriStateCheckBox proxy = findByName(panel, "fields.traffic.section.burp.proxy", TriStateCheckBox.class);
        JCheckBox notes = findByName(panel, "fields.traffic.burp.notes", JCheckBox.class);
        JCheckBox proxyHistoryId = findByName(panel, "fields.traffic.burp.proxy.history_id", JCheckBox.class);

        runEdt(() -> {
            trafficExpand.doClick();
            burpExpand.doClick();
            layoutTree(panel);

            assertThat(absoluteX(notes, panel) - absoluteX(burp, panel)).isGreaterThanOrEqualTo(55);
            assertThat(absoluteX(proxyHistoryId, panel) - absoluteX(proxy, panel)).isGreaterThanOrEqualTo(55);
        });
    }

    private static ConfigPanel newPanelOnEdt() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel();
            panel.setSize(1000, 900);
            layoutTree(panel);
            ref.set(panel);
        });
        return ref.get();
    }

    private static void runEdt(Runnable runnable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        for (Component component : root.getComponents()) {
            String componentName = component.getName();
            if (type.isInstance(component) && componentName != null && name.equals(componentName)) {
                return type.cast(component);
            }
            if (component instanceof Container child) {
                T nested = findByName(child, name, type);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static int absoluteX(Component component, Component root) {
        assertThat(component).isNotNull();
        Point point = SwingUtilities.convertPoint(component.getParent(), component.getLocation(), root);
        return point.x;
    }

    private static void layoutTree(Container container) {
        container.doLayout();
        for (Component component : container.getComponents()) {
            if (component instanceof Container child) {
                layoutTree(child);
            }
        }
    }
}
