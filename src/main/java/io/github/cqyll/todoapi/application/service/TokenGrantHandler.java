package io.github.cqyll.todoapi.application.service;

import io.github.cqyll.todoapi.application.service.OAuthTokenService.GrantContext;
import io.github.cqyll.todoapi.domain.OAuthClient;
import io.github.cqyll.todoapi.dto.OAuthTokenRequest;

import java.util.Map;

public interface TokenGrantHandler {
	OAuthClient.GrantType supports();
	Map<String, Object> handle(GrantContext ctx, OAuthTokenRequest req);
}