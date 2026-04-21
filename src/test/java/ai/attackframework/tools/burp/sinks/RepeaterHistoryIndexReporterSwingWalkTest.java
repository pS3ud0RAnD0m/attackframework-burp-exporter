package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

class RepeaterHistoryIndexReporterSwingWalkTest {

    @Test
    void inferRepeaterTabName_returnsSelectedTabLabel_whenGroupedHeaderAlsoContainsGroupName() throws Exception {
        AtomicReference<String> tabNameRef = new AtomicReference<>();
        AtomicReference<String> groupNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane groupedTabs = new JTabbedPane();
            groupedTabs.addTab("2", new JPanel());
            groupedTabs.addTab("3", new JPanel());
            groupedTabs.setSelectedIndex(0);

            JPanel tabHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            tabHeader.add(new JLabel("myRepeaterGroup"));
            tabHeader.add(new JLabel("2"));
            tabHeader.add(new JLabel("3"));
            tabHeader.add(new JLabel("382"));
            JButton closeButton = new JButton();
            closeButton.setName("tabbedPaneTabCloseButton");
            tabHeader.add(closeButton);
            groupedTabs.setTabComponentAt(0, tabHeader);

            JTabbedPane auxiliaryTabs = new JTabbedPane();
            auxiliaryTabs.addTab("Inspector", new JPanel());
            auxiliaryTabs.addTab("Custom actions", new JPanel());
            auxiliaryTabs.setSelectedIndex(0);

            JPanel selectedTabBody = new JPanel(new BorderLayout());
            selectedTabBody.add(auxiliaryTabs, BorderLayout.CENTER);
            groupedTabs.setComponentAt(0, selectedTabBody);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(groupedTabs, BorderLayout.CENTER);

            tabNameRef.set(RepeaterHistoryIndexReporter.inferRepeaterTabName(repeaterRoot));
            groupNameRef.set(RepeaterHistoryIndexReporter.inferRepeaterGroupName(repeaterRoot));
        });

        assertThat(tabNameRef.get()).isEqualTo("2");
        assertThat(groupNameRef.get()).isEqualTo("myRepeaterGroup");
    }

    @Test
    void inferRepeaterGroupName_usesSiblingPaneTitle_whenBurpStoresGroupOutsideSelectedHeader() throws Exception {
        AtomicReference<String> tabNameRef = new AtomicReference<>();
        AtomicReference<String> groupNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane groupedTabs = new JTabbedPane();
            groupedTabs.addTab("myRepeaterGroup", new JPanel());
            groupedTabs.addTab("2", new JPanel());
            groupedTabs.addTab("382", new JPanel());
            groupedTabs.setSelectedIndex(1);
            groupedTabs.setTabComponentAt(0, groupHeader("myRepeaterGroup", "2"));
            groupedTabs.setTabComponentAt(1, new JLabel("2"));
            groupedTabs.setTabComponentAt(2, new JLabel("382"));

            JTabbedPane auxiliaryTabs = new JTabbedPane();
            auxiliaryTabs.addTab("Inspector", new JPanel());
            auxiliaryTabs.addTab("Custom actions", new JPanel());
            auxiliaryTabs.setSelectedIndex(0);

            JPanel selectedTabBody = new JPanel(new BorderLayout());
            selectedTabBody.add(auxiliaryTabs, BorderLayout.CENTER);
            groupedTabs.setComponentAt(1, selectedTabBody);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(groupedTabs, BorderLayout.CENTER);

            tabNameRef.set(RepeaterHistoryIndexReporter.inferRepeaterTabName(repeaterRoot));
            groupNameRef.set(RepeaterHistoryIndexReporter.inferRepeaterGroupName(repeaterRoot));
        });

        assertThat(tabNameRef.get()).isEqualTo("2");
        assertThat(groupNameRef.get()).isEqualTo("myRepeaterGroup");
    }

    @Test
    void inferRepeaterGroupName_returnsSelectedOuterTabLabel_whenGrouped() throws Exception {
        AtomicReference<String> groupNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane responseTabs = new JTabbedPane();
            responseTabs.addTab("Raw", new JPanel());
            responseTabs.addTab("Pretty", new JPanel());

            JTabbedPane groupedRequests = new JTabbedPane();
            groupedRequests.addTab("Req A", new JPanel());
            JPanel groupedRequestView = new JPanel(new BorderLayout());
            groupedRequestView.add(responseTabs, BorderLayout.CENTER);
            groupedRequests.addTab("Req B", groupedRequestView);
            groupedRequests.setSelectedIndex(1);

            JTabbedPane groupTabs = new JTabbedPane();
            groupTabs.addTab("Group Alpha", groupedRequests);
            groupTabs.addTab("Group Beta", new JPanel());
            groupTabs.setSelectedIndex(0);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(groupTabs, BorderLayout.CENTER);

            groupNameRef.set(RepeaterHistoryIndexReporter.inferRepeaterGroupName(repeaterRoot));
        });

        assertThat(groupNameRef.get()).isEqualTo("Group Alpha");
    }

    @Test
    void inferRepeaterTabName_returnsSelectedTabLabel_whenNoGroupContainerExists() throws Exception {
        AtomicReference<String> tabNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane repeaterTabs = new JTabbedPane();
            repeaterTabs.addTab("Req A", new JPanel());
            repeaterTabs.addTab("Req B", new JPanel());
            repeaterTabs.setSelectedIndex(1);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);

            tabNameRef.set(RepeaterHistoryIndexReporter.inferRepeaterTabName(repeaterRoot));
        });

        assertThat(tabNameRef.get()).isEqualTo("Req B");
    }

    @Test
    void inferRepeaterGroupName_returnsNull_whenNoGroupContainerExists() throws Exception {
        AtomicReference<String> groupNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane repeaterTabs = new JTabbedPane();
            repeaterTabs.addTab("Req A", new JPanel());
            repeaterTabs.addTab("Req B", new JPanel());
            repeaterTabs.setSelectedIndex(1);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);

            groupNameRef.set(RepeaterHistoryIndexReporter.inferRepeaterGroupName(repeaterRoot));
        });

        assertThat(groupNameRef.get()).isNull();
    }

    @Test
    void performStartupTabWalk_visitsRepeaterToolTree_andRestoresSelections() throws Exception {
        AtomicReference<RepeaterHistoryIndexReporter.StartupTabWalkResult> resultRef = new AtomicReference<>();
        AtomicReference<JTabbedPane> toolTabsRef = new AtomicReference<>();
        AtomicReference<JTabbedPane> repeaterTabsRef = new AtomicReference<>();
        AtomicReference<JTabbedPane> responseTabsRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane responseTabs = new JTabbedPane();
            responseTabs.addTab("Raw", new JPanel());
            responseTabs.addTab("Pretty", new JPanel());
            responseTabs.setSelectedIndex(1);

            JPanel secondRepeaterTab = new JPanel(new BorderLayout());
            secondRepeaterTab.add(responseTabs, BorderLayout.CENTER);

            JTabbedPane repeaterTabs = new JTabbedPane();
            repeaterTabs.addTab("Req A", new JPanel());
            repeaterTabs.addTab("Req B", secondRepeaterTab);
            repeaterTabs.addTab("Req C", new JPanel());
            repeaterTabs.setSelectedIndex(2);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);

            JTabbedPane toolTabs = new JTabbedPane();
            toolTabs.addTab("Dashboard", new JPanel());
            toolTabs.addTab("Repeater", repeaterRoot);
            toolTabs.addTab("Proxy", new JPanel());
            toolTabs.setSelectedIndex(0);

            JPanel root = new JPanel(new BorderLayout());
            root.add(toolTabs, BorderLayout.CENTER);

            resultRef.set(RepeaterHistoryIndexReporter.performStartupTabWalk(List.of(root)));
            toolTabsRef.set(toolTabs);
            repeaterTabsRef.set(repeaterTabs);
            responseTabsRef.set(responseTabs);
        });

        RepeaterHistoryIndexReporter.StartupTabWalkResult result = resultRef.get();
        assertThat(result.locatedRepeaterToolTab()).isTrue();
        assertThat(result.tabbedPaneCount()).isEqualTo(1);
        assertThat(result.selectionChangeCount()).isEqualTo(4);
        assertThat(toolTabsRef.get().getSelectedIndex()).isEqualTo(0);
        assertThat(repeaterTabsRef.get().getSelectedIndex()).isEqualTo(2);
        assertThat(responseTabsRef.get().getSelectedIndex()).isEqualTo(1);
    }

    @Test
    void performStartupTabWalk_returnsNotLocated_whenRepeaterToolTabMissing() throws Exception {
        AtomicReference<RepeaterHistoryIndexReporter.StartupTabWalkResult> resultRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane toolTabs = new JTabbedPane();
            toolTabs.addTab("Dashboard", new JPanel());
            toolTabs.addTab("Proxy", new JPanel());

            JPanel root = new JPanel(new BorderLayout());
            root.add(toolTabs, BorderLayout.CENTER);

            resultRef.set(RepeaterHistoryIndexReporter.performStartupTabWalk(List.of(root)));
        });

        RepeaterHistoryIndexReporter.StartupTabWalkResult result = resultRef.get();
        assertThat(result.locatedRepeaterToolTab()).isFalse();
        assertThat(result.tabbedPaneCount()).isZero();
        assertThat(result.selectionChangeCount()).isZero();
    }

    private static JPanel groupHeader(String groupName, String childCount) {
        JPanel tabHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        tabHeader.add(new JLabel(groupName));
        tabHeader.add(new JLabel(childCount));
        return tabHeader;
    }
}
