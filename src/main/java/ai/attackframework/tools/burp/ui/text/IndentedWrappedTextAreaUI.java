package ai.attackframework.tools.burp.ui.text;

import javax.swing.plaf.basic.BasicTextAreaUI;
import javax.swing.text.Element;
import javax.swing.text.View;

/**
 * Text area UI that uses {@link IndentedWrappedPlainView} so wrapped lines
 * get a continuation indent in the log panel.
 */
public final class IndentedWrappedTextAreaUI extends BasicTextAreaUI {

    @Override
    public View create(Element elem) {
        return new IndentedWrappedPlainView(elem);
    }
}
