package io.github.cqyll.todoapi.application.port.outbound;

import java.util.Set;

public interface TokenProviderPort {
	String createAccessToken(String subject, String clientId, Set<String> scopes);
	String createRefreshToken(String subject, String clientId, Set<String> scopes);
}
