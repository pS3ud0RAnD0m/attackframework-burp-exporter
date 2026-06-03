package ai.attackframework.tools.burp.sinks;

/**
 * Helpers for tests that assert {@link TrafficExportQueue} depth without racing the drain worker.
 */
final class TrafficExportQueueTestSupport {

    private TrafficExportQueueTestSupport() {}

    /**
     * Runs {@code action} with the drain worker suppressed so offered documents remain in the queue.
     */
    static void withDrainWorkerDisabled(ThrowingRunnable action) throws Exception {
        TrafficExportQueue.setDrainDisabledForTests(true);
        try {
            TrafficExportQueue.stopWorker();
            TrafficExportQueue.clearPendingWork();
            action.run();
        } finally {
            TrafficExportQueue.setDrainDisabledForTests(false);
            TrafficExportQueue.stopWorker();
            TrafficExportQueue.clearPendingWork();
        }
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }
}
