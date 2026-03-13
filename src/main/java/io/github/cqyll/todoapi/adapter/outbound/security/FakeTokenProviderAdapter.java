package io.github.cqyll.todoapi.adapter.outbound.security;

import java.util.Set;

import io.github.cqyll.todoapi.application.port.outbound.TokenProviderPort;

public class FakeTokenProviderAdapter implements TokenProviderPort {
	public String createAccessToken(String subject, String clientId, Set<String> scopes) {
		return "ACCESS-" + subject;
	}
	
	public String createRefreshToken(String subject, String clientId, Set<String> scopes) {
		return "REFRESH-" + subject;
	}
}
