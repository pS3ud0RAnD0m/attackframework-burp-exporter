package ai.attackframework.tools.burp.ui.text;

import java.awt.Container;

import javax.swing.text.BoxView;
import javax.swing.text.Element;
import javax.swing.text.StyledEditorKit;
import javax.swing.text.View;
import javax.swing.text.ViewFactory;

/**
 * Styled editor kit that wraps long lines so no horizontal scroll bar is needed.
 * The root view constrains width to the container; default paragraph view handles wrapping.
 */
public final class WrappingStyledEditorKit extends StyledEditorKit {

    private static final long serialVersionUID = 1L;

    private static final ViewFactory DEFAULT_FACTORY = new StyledEditorKit().getViewFactory();

    @Override
    public ViewFactory getViewFactory() {
        return new WrapViewFactory();
    }

    private static final class WrapViewFactory implements ViewFactory {
        @Override
        public View create(Element elem) {
            if (elem.getParentElement() == null) {
                return new WrapColumnView(elem, View.Y_AXIS);
            }
            return DEFAULT_FACTORY.create(elem);
        }
    }

    /**
     * Root view that constrains width to the container so child paragraphs wrap.
     */
    private static final class WrapColumnView extends BoxView {
        WrapColumnView(Element elem, int axis) {
            super(elem, axis);
        }

        @Override
        public float getPreferredSpan(int axis) {
            if (axis == View.X_AXIS) {
                Container c = getContainer();
                if (c != null) {
                    float w = (float) c.getWidth();
                    if (w > 0) {
                        return Math.min(w, super.getPreferredSpan(axis));
                    }
                }
            }
            return super.getPreferredSpan(axis);
        }
    }
}
