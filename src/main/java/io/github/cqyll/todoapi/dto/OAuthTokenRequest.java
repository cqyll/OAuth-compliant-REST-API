package io.github.cqyll.todoapi.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Locale;
import java.util.Objects;


/**
 * DTO representing an OAuth 2.0 token request.
 *
 * <p>This DTO accepts fields that can come from
 * application/x-www-form-urlencoded bodies and/or HTTP Basic Authorization header
 * (client_id/client_secret can be supplied either way).</p>
 */
public final class OAuthTokenRequest {
	private final String grantType;
	// Client authentication (either via Basic auth header or request body)
	private final String clientId;
	private final String clientSecret;

	private final String username;
	private final String password;
	private final String code;
	private final String redirectUri;
	private final String refreshToken;
	private final String scope;

	@JsonCreator
	public OAuthTokenRequest(
			@JsonProperty("grant_type") String grantType,
			@JsonProperty("client_id") String clientId,
			@JsonProperty("client_secret") String clientSecret,
			@JsonProperty("username") String username,
			@JsonProperty("password") String password,
			@JsonProperty("code") String code,
			@JsonProperty("redirect_uri") String redirectUri,
			@JsonProperty("refresh_token") String refreshToken,
			@JsonProperty("scope") String scope
			) {
		this.grantType = normalizeGrantType(grantType);

		this.clientId = trimToNull(clientId);
		this.clientSecret = trimToNull(clientSecret);

		this.username = trimToNull(username);
		this.password = trimToNull(password);

		this.code = trimToNull(code);
		this.redirectUri = trimToNull(redirectUri);

		this.refreshToken = trimToNull(refreshToken);

		this.scope = trimToNull(scope);
	}

	public String getGrantType() { return grantType; }
	public String getClientId() { return clientId; }
	public String getClientSecret() { return clientSecret; }
	public String getUsername() { return username; }
	public String getPassword() { return password; }
	public String getCode() { return code; }
	public String getRedirectUri() { return redirectUri; }
	public String getRefreshToken() { return refreshToken; }
	public String getScope() { return scope; }

	private static String normalizeGrantType(String raw) {
		String v = trimToNull(raw);
		return v == null ? null : v.toLowerCase(Locale.ROOT);
	}

	private static String trimToNull(String s) {
		if (s == null) return null;
		String t = s.trim();
		return t.isEmpty() ? null : t;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof OAuthTokenRequest)) return false;
		OAuthTokenRequest other = (OAuthTokenRequest) o;
		return Objects.equals(grantType, other.grantType)
				&& Objects.equals(clientId, other.clientId)
				&& Objects.equals(clientSecret, other.clientSecret)
				&& Objects.equals(username, other.username)
				&& Objects.equals(password, other.password)
				&& Objects.equals(code, other.code)
				&& Objects.equals(redirectUri, other.redirectUri)
				&& Objects.equals(refreshToken, other.refreshToken)
				&& Objects.equals(scope, other.scope);
	}

	@Override
	public int hashCode() {
		return Objects.hash(grantType, clientId, clientSecret, username, password, code, redirectUri, refreshToken, scope);
	}

	
	// consider adding redaction helper, so toString can include redacted values for sensitive fields (e.g., clientSecret, password, refreshToken)
	@Override
	public String toString() {
		return "OAuthTokenRequest{" +
				"grantType='" + grantType + '\'' +
				", clientId='" + clientId + '\'' +
				", username='" + username + '\'' +
				", code='" + code + '\'' +
				", redirectUri='" + redirectUri + '\'' +
				", scope=" + scope +
				'}';
	}
}