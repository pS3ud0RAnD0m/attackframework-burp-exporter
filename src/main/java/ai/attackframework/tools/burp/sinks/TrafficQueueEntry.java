package ai.attackframework.tools.burp.sinks;

import java.util.Map;

import ai.attackframework.tools.burp.utils.export.ExportDocumentIdentity;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

/**
 * One traffic export item prepared once at enqueue time for the live drain path.
 *
 * <p>Spill files preserve prepared entries when possible so overflow/refill does not repeat
 * filtering or NDJSON serialization. Legacy raw-map spill files are still prepared during
 * recovery.</p>
 */
public final class TrafficQueueEntry {

    private final PreparedExportDocument prepared;

    private TrafficQueueEntry(PreparedExportDocument prepared) {
        this.prepared = prepared;
    }

    static TrafficQueueEntry fromPrepared(PreparedExportDocument prepared) {
        if (prepared == null) {
            return null;
        }
        return new TrafficQueueEntry(prepared);
    }

    public static TrafficQueueEntry from(Map<String, Object> document) {
        if (document == null) {
            return null;
        }
        return new TrafficQueueEntry(ExportDocumentIdentity.prepare(
                TrafficRouteBucket.trafficIndexName(), TrafficRouteBucket.INDEX_KEY, document));
    }

    public PreparedExportDocument prepared() {
        return prepared;
    }

    public Map<String, Object> document() {
        return prepared.document();
    }
}
