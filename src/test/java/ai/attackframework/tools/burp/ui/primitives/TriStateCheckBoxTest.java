package ai.attackframework.tools.burp.ui.primitives;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.ui.primitives.TriStateCheckBox.State;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link TriStateCheckBox} and {@link TriStateCheckBox.TriStateButtonModel} state behaviour.
 */
class TriStateCheckBoxTest {

    @Test
    void initialState_respected() {
        assertThat(new TriStateCheckBox("x", State.DESELECTED).getState()).isEqualTo(State.DESELECTED);
        assertThat(new TriStateCheckBox("x", State.SELECTED).getState()).isEqualTo(State.SELECTED);
        assertThat(new TriStateCheckBox("x", State.INDETERMINATE).getState()).isEqualTo(State.INDETERMINATE);
    }

    @Test
    void nullInitialState_treatedAsDeselected() {
        TriStateCheckBox box = new TriStateCheckBox("x", null);
        assertThat(box.getState()).isEqualTo(State.DESELECTED);
    }

    @Test
    void setState_getState_roundTrip_allStates() {
        TriStateCheckBox box = new TriStateCheckBox("", State.DESELECTED);

        box.setState(State.SELECTED);
        assertThat(box.getState()).isEqualTo(State.SELECTED);

        box.setState(State.INDETERMINATE);
        assertThat(box.getState()).isEqualTo(State.INDETERMINATE);

        box.setState(State.DESELECTED);
        assertThat(box.getState()).isEqualTo(State.DESELECTED);

        box.setState(null);
        assertThat(box.getState()).isEqualTo(State.DESELECTED);
    }

    @Test
    void setIndeterminate_setsIndeterminateState() {
        TriStateCheckBox box = new TriStateCheckBox("", State.DESELECTED);
        box.setIndeterminate();
        assertThat(box.getState()).isEqualTo(State.INDETERMINATE);
        assertThat(box.isIndeterminate()).isTrue();
    }

    @Test
    void isIndeterminate_trueOnlyWhenStateIndeterminate() {
        TriStateCheckBox box = new TriStateCheckBox("", State.DESELECTED);
        assertThat(box.isIndeterminate()).isFalse();

        box.setState(State.SELECTED);
        assertThat(box.isIndeterminate()).isFalse();

        box.setState(State.INDETERMINATE);
        assertThat(box.isIndeterminate()).isTrue();

        box.setState(State.DESELECTED);
        assertThat(box.isIndeterminate()).isFalse();
    }

    @Test
    void setSelected_mapsToSelectedOrDeselectedState() {
        TriStateCheckBox box = new TriStateCheckBox("", State.INDETERMINATE);
        box.getTriStateModel().setSelected(true);
        assertThat(box.getState()).isEqualTo(State.SELECTED);
        box.getTriStateModel().setSelected(false);
        assertThat(box.getState()).isEqualTo(State.DESELECTED);
    }

    @Test
    void getTriStateModel_returnsSameModelAsGetModel() {
        TriStateCheckBox box = new TriStateCheckBox("", State.SELECTED);
        assertThat(box.getTriStateModel()).isSameAs(box.getModel());
    }
}
