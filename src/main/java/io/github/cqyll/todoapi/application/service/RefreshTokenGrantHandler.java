package io.github.cqyll.todoapi.application.service;

import java.util.LinkedHashMap;
import java.util.Map;

import io.github.cqyll.todoapi.adapter.inbound.web.OAuthError;
import io.github.cqyll.todoapi.application.port.outbound.RefreshTokenRecord;
import io.github.cqyll.todoapi.application.port.outbound.RefreshTokenRepositoryPort;
import io.github.cqyll.todoapi.application.port.outbound.TokenProviderPort;
import io.github.cqyll.todoapi.application.service.OAuthTokenService.GrantContext;
import io.github.cqyll.todoapi.domain.OAuthClient;
import io.github.cqyll.todoapi.dto.OAuthTokenRequest;

public class RefreshTokenGrantHandler implements TokenGrantHandler {
	private final TokenProviderPort tokens;
	private final RefreshTokenRepositoryPort refreshTokens;
	
	public RefreshTokenGrantHandler(TokenProviderPort tokens, RefreshTokenRepositoryPort refreshTokens) {
		this.tokens = tokens;
		this.refreshTokens = refreshTokens;
	}
	
	@Override
	public OAuthClient.GrantType supports() {
		return OAuthClient.GrantType.REFRESH_TOKEN;
	}
	
	@Override
	public Map<String, Object> handle(GrantContext ctx, OAuthTokenRequest req) {
		String refreshToken = 
				requireNonBlank(req.getRefreshToken(), "refresh_token is required for refresh_token grant");
		
		rejectIfPresent(req.getUsername(), "username is not allowed for refresh_token grant");
		rejectIfPresent(req.getPassword(), "password is not allowed for refresh_token grant");
		rejectIfPresent(req.getCode(), "code is not allowed for refresh_token grant");
		rejectIfPresent(req.getRedirectUri(), "redirect_uri is not allowed for refresh_token grant");
		
		RefreshTokenRecord stored = refreshTokens.findByToken(refreshToken)
				.orElseThrow(() -> OAuthError.invalidGrant("invalid refresh token"));
		
		if (!stored.isActive() || stored.isExpired()) {
			throw OAuthError.invalidGrant("invalid refresh token");
		}
		
		if (!stored.getClientId().equals(ctx.client().getClientId())) {
			throw OAuthError.invalidGrant("invalid refresh token");
		}
		
		String subject = stored.getSubject();
		String clientId = stored.getClientId();
		
		String access = tokens.createAccessToken(subject, clientId, stored.getScopes());
		String newRefresh = tokens.createRefreshToken(subject, clientId, stored.getScopes());
		
		refreshTokens.revoke(refreshToken);
		refreshTokens.save(new RefreshTokenRecord(
				newRefresh,
				subject,
				clientId,
				stored.getScopes(),
				System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000,
				true
		));
		
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("access_token", access);
		out.put("token_type", "Bearer");
		out.put("expires_in", 3600);
		out.put("refresh_token", newRefresh);
		
		if (!stored.getScopes().isEmpty()) {
			out.put("scope", String.join(" ", stored.getScopes()));
		}
		
		return out;
	}
	
	private static String requireNonBlank(String v, String msg) {
		if (v == null || v.isBlank()) throw OAuthError.invalidRequest(msg);
		return v;
	}
	
	private static void rejectIfPresent(String v, String msg) {
		if (v != null && !v.isBlank()) throw OAuthError.invalidRequest(msg);
	}
}
