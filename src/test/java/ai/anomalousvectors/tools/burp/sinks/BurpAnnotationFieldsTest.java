package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;

class BurpAnnotationFieldsTest {

    @Test
    void put_noOpWhenBurpOrAnnotationsNull() {
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", "Proxy");

        BurpAnnotationFields.put(null, mock(Annotations.class));
        BurpAnnotationFields.put(burp, null);

        assertThat(burp).containsOnlyKeys("reporting_tool");
    }

    @Test
    void put_writesNotesWhenPresent() {
        Map<String, Object> burp = new LinkedHashMap<>();
        Annotations annotations = mock(Annotations.class);
        when(annotations.hasNotes()).thenReturn(true);
        when(annotations.hasHighlightColor()).thenReturn(false);
        when(annotations.notes()).thenReturn("review this");

        BurpAnnotationFields.put(burp, annotations);

        assertThat(burp.get("notes")).isEqualTo("review this");
        assertThat(burp).doesNotContainKey("highlight");
    }

    @Test
    void put_writesHighlightWhenPresent() {
        Map<String, Object> burp = new LinkedHashMap<>();
        Annotations annotations = mock(Annotations.class);
        when(annotations.hasNotes()).thenReturn(false);
        when(annotations.hasHighlightColor()).thenReturn(true);
        when(annotations.highlightColor()).thenReturn(HighlightColor.RED);

        BurpAnnotationFields.put(burp, annotations);

        assertThat(burp.get("highlight")).isEqualTo("RED");
        assertThat(burp).doesNotContainKey("notes");
    }
}
