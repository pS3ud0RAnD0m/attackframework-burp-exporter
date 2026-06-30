package ai.anomalousvectors.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import javax.swing.JCheckBox;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.ui.primitives.TriStateCheckBox;
import ai.anomalousvectors.tools.burp.ui.primitives.TriStateCheckBox.State;

/**
 * Unit tests for {@link FieldSectionSelectionWiring} parent/child tri-state propagation.
 */
class FieldSectionSelectionWiringTest {

    @Test
    void wireTriStateParentChild_reflectsPartialChildSelectionAsIndeterminate() {
        TriStateCheckBox parent = new TriStateCheckBox("Section", State.SELECTED);
        JCheckBox childA = new JCheckBox("A", true);
        JCheckBox childB = new JCheckBox("B", true);

        FieldSectionSelectionWiring.wireTriStateParentChild(parent, List.of(childA, childB));

        childA.setSelected(false);
        assertThat(parent.getState()).isEqualTo(State.INDETERMINATE);

        childA.setSelected(true);
        assertThat(parent.getState()).isEqualTo(State.SELECTED);
    }

    @Test
    void wireTriStateParentChild_parentClickDeselectsAllEnabledChildren() {
        TriStateCheckBox parent = new TriStateCheckBox("Section", State.SELECTED);
        JCheckBox childA = new JCheckBox("A", true);
        JCheckBox childB = new JCheckBox("B", true);

        FieldSectionSelectionWiring.wireTriStateParentChild(parent, List.of(childA, childB));

        parent.setState(State.DESELECTED);
        parent.getActionListeners()[0].actionPerformed(
                new java.awt.event.ActionEvent(parent, java.awt.event.ActionEvent.ACTION_PERFORMED, ""));

        assertThat(childA.isSelected()).isFalse();
        assertThat(childB.isSelected()).isFalse();
        assertThat(parent.getState()).isEqualTo(State.DESELECTED);
    }

    @Test
    void wireTriStateParentChild_parentClickFromPartialSelectsAllChildren() {
        TriStateCheckBox parent = new TriStateCheckBox("Section", State.SELECTED);
        JCheckBox childA = new JCheckBox("A", true);
        JCheckBox childB = new JCheckBox("B", true);

        FieldSectionSelectionWiring.wireTriStateParentChild(parent, List.of(childA, childB));
        childB.setSelected(false);
        assertThat(parent.getState()).isEqualTo(State.INDETERMINATE);

        parent.setState(State.SELECTED);
        parent.getActionListeners()[0].actionPerformed(
                new java.awt.event.ActionEvent(parent, java.awt.event.ActionEvent.ACTION_PERFORMED, ""));

        assertThat(childA.isSelected()).isTrue();
        assertThat(childB.isSelected()).isTrue();
        assertThat(parent.getState()).isEqualTo(State.SELECTED);
    }
}
