package io.github.cqyll.todoapi.application.port.outbound;

import java.util.Set;

public final class RefreshTokenRecord {
	private final String token;
	private final String subject;
	private final String clientId;
	private final Set<String> scopes;
	private final long expiresAtEpochMillis;
	private final boolean active;
	
	public RefreshTokenRecord(
			String token,
			String subject,
			String clientId,
			Set<String> scopes,
			long expiresAtEpochMillis,
			boolean active) {
		if (token == null || token.isBlank()) throw new IllegalArgumentException("token is required");
		if (subject == null || subject.isBlank()) throw new IllegalArgumentException("subject is required");
		if (clientId == null || clientId.isBlank()) throw new IllegalArgumentException("clientId is required");
		if (scopes == null) throw new IllegalArgumentException("scopes are required");
		
		this.token = token;
		this.subject = subject;
		this.clientId = clientId;
		this.scopes = Set.copyOf(scopes);
		this.expiresAtEpochMillis = expiresAtEpochMillis;
		this.active = active;
	}

	public String getToken() {
		return token;
	}

	public String getSubject() {
		return subject;
	}

	public String getClientId() {
		return clientId;
	}

	public Set<String> getScopes() {
		return scopes;
	}

	public long getExpiresAtEpochMillis() {
		return expiresAtEpochMillis;
	}

	public boolean isActive() {
		return active;
	}
	
	
	public boolean isExpired() {
		return System.currentTimeMillis() >= expiresAtEpochMillis;
	}
	
	public RefreshTokenRecord revoked() {
		return new RefreshTokenRecord(token, subject, clientId, scopes, expiresAtEpochMillis, false);
	}
}
