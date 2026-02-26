package io.github.cqyll.todoapi.adapter.inbound.web;

@SuppressWarnings("serial")
public final class OAuthError extends RuntimeException {
    private final String error;
    private final String description;
    private final String uri;
    private final int httpStatus;

    private OAuthError(String error, String description, String uri, int httpStatus) {
        super(error);
        this.error = error;
        this.description = description;
        this.uri = uri;
        this.httpStatus = httpStatus;
    }

    public String getError() { return error; }
    public String getDescription() { return description; }
    public String getUri() { return uri; }
    public int getHttpStatus() { return httpStatus; }

    // RFC 6749 token endpoint errors:
    public static OAuthError invalidRequest(String desc) {
        return new OAuthError("invalid_request", desc, null, 400);
    }

    public static OAuthError invalidClient(String desc) {
        // Typically 401 with WWW-Authenticate
        return new OAuthError("invalid_client", desc, null, 401);
    }

    public static OAuthError invalidGrant(String desc) {
        return new OAuthError("invalid_grant", desc, null, 400);
    }

    public static OAuthError unauthorizedClient(String desc) {
        return new OAuthError("unauthorized_client", desc, null, 400);
    }

    public static OAuthError unsupportedGrantType(String desc) {
        return new OAuthError("unsupported_grant_type", desc, null, 400);
    }

    public static OAuthError invalidScope(String desc) {
        return new OAuthError("invalid_scope", desc, null, 400);
    }

    public static OAuthError serverError() {
        return new OAuthError("server_error", null, null, 500);
    }
}
