package io.github.cqyll.todoapi.adapter.outbound.security;

import io.github.cqyll.todoapi.application.port.outbound.TokenProviderPort;

public class FakeTokenProviderAdapter implements TokenProviderPort {

	@Override
	public String createToken(String subject) {
		return "TOKEN-" + subject;
	}
}
