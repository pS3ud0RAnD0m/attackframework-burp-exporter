package ai.attackframework.tools.burp.utils.opensearch;

/** Thrown when an OpenSearch client cannot be constructed. */
public final class OpenSearchClientBuildException extends RuntimeException {
    public OpenSearchClientBuildException(String message, Throwable cause) {
        super(message, cause);
    }
}
