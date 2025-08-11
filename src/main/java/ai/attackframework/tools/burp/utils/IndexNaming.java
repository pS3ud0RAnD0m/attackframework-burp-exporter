package ai.attackframework.tools.burp.utils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

public final class IndexNaming {
    public static final String INDEX_PREFIX = "attackframework-tool-burp";

    private IndexNaming() {}

    public static List<String> computeIndexBaseNames(List<String> selectedSources) {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        if (selectedSources != null) {
            for (String s : selectedSources) {
                if (s == null) continue;
                switch (s.toLowerCase()) {
                    case "settings" -> names.add(INDEX_PREFIX + "-settings");
                    case "sitemap"  -> names.add(INDEX_PREFIX + "-sitemap");
                    case "issues", "findings" -> names.add(INDEX_PREFIX + "-findings");
                    case "traffic"  -> names.add(INDEX_PREFIX + "-traffic");
                }
            }
        }
        names.add(INDEX_PREFIX);
        return new ArrayList<>(names);
    }

    public static List<String> toJsonFileNames(List<String> baseNames) {
        List<String> out = new ArrayList<>(baseNames.size());
        for (String b : baseNames) out.add(b + ".json");
        return out;
    }
}
