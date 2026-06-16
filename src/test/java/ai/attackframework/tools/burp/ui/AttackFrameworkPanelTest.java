package ai.attackframework.tools.burp.ui;

import static ai.attackframework.tools.burp.ui.text.Tooltips.TOOLTIP_SHOW_DELAY_MS;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.ui.text.Tooltips;

class AttackFrameworkPanelTest {

    @Test
    void extensionUi_usesSharedTooltipShowDelay() throws Exception {
        AtomicInteger previousInitialDelay = new AtomicInteger();
        AtomicInteger previousReshowDelay = new AtomicInteger();
        AtomicInteger previousDismissDelay = new AtomicInteger();
        AtomicInteger actualInitialDelay = new AtomicInteger();
        AtomicInteger actualReshowDelay = new AtomicInteger();
        AtomicInteger actualDismissDelay = new AtomicInteger();

        SwingUtilities.invokeAndWait(() -> {
            ToolTipManager manager = ToolTipManager.sharedInstance();
            previousInitialDelay.set(manager.getInitialDelay());
            previousReshowDelay.set(manager.getReshowDelay());
            previousDismissDelay.set(manager.getDismissDelay());
        });
        try {
            SwingUtilities.invokeAndWait(Tooltips::configureSharedToolTipManager);
            SwingUtilities.invokeAndWait(() -> new AttackFrameworkPanel());
            SwingUtilities.invokeAndWait(() -> {
                ToolTipManager manager = ToolTipManager.sharedInstance();
                actualInitialDelay.set(manager.getInitialDelay());
                actualReshowDelay.set(manager.getReshowDelay());
                actualDismissDelay.set(manager.getDismissDelay());
            });

            assertThat(actualInitialDelay.get()).isEqualTo(TOOLTIP_SHOW_DELAY_MS);
            assertThat(actualReshowDelay.get()).isEqualTo(TOOLTIP_SHOW_DELAY_MS);
            assertThat(actualDismissDelay.get()).isEqualTo(Integer.MAX_VALUE);
        } finally {
            SwingUtilities.invokeAndWait(() -> {
                ToolTipManager manager = ToolTipManager.sharedInstance();
                manager.setInitialDelay(previousInitialDelay.get());
                manager.setReshowDelay(previousReshowDelay.get());
                manager.setDismissDelay(previousDismissDelay.get());
            });
        }
    }
}
