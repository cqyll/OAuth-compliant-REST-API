package io.github.cqyll.todoapi.application.service;

import io.github.cqyll.todoapi.application.port.outbound.PasswordHasherPort;
import io.github.cqyll.todoapi.application.port.outbound.RefreshTokenRecord;
import io.github.cqyll.todoapi.application.port.outbound.RefreshTokenRepositoryPort;
import io.github.cqyll.todoapi.application.port.outbound.TokenProviderPort;
import io.github.cqyll.todoapi.application.port.outbound.UserRepositoryPort;
import io.github.cqyll.todoapi.application.service.OAuthTokenService.GrantContext;
import io.github.cqyll.todoapi.domain.OAuthClient;
import io.github.cqyll.todoapi.domain.User;
import io.github.cqyll.todoapi.dto.OAuthTokenRequest;
import io.github.cqyll.todoapi.adapter.inbound.web.OAuthError;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class PasswordGrantHandler implements TokenGrantHandler {
    
	private static final long REFRESH_TOKEN_TTL_MILLIS = 30L * 24 * 60 * 60 * 1000;
	
	private final UserRepositoryPort users;
    private final PasswordHasherPort hasher;
    private final TokenProviderPort tokens;
    private final RefreshTokenRepositoryPort refreshTokens;
    
    public PasswordGrantHandler(UserRepositoryPort users, PasswordHasherPort hasher, TokenProviderPort tokens, RefreshTokenRepositoryPort refreshTokens) {
        this.hasher = hasher;
        this.users = users;
        this.tokens = tokens;
        this.refreshTokens = refreshTokens;
    }

    @Override
    public OAuthClient.GrantType supports() {
    	return OAuthClient.GrantType.PASSWORD;
    }
    
    @Override
    public Map<String, Object> handle(GrantContext ctx, OAuthTokenRequest req) {
    	String username = requireNonBlank(req.getUsername(), "username is required for password grant.");
    	String password = requireNonBlank(req.getPassword(), "password is required for password grant.");
    	
    	// reject other grant params early
    	rejectIfPresent(req.getCode(), "code is not allowed for password grant");
    	rejectIfPresent(req.getRedirectUri(), "redirect_uri is not allowed for password grant");
    	rejectIfPresent(req.getRefreshToken(), "refresh_token is not allowed for password grant");
    	
    	User user = users.findByEmail(username)
    			.orElseThrow(() -> OAuthError.invalidGrant("invalid resource owner credentials"));
    	
    	if (!user.verifyPassword(password, hasher) || !user.isActive()) {
    		throw OAuthError.invalidGrant("invalid resource owner credentials");
    	}
    	
    	String subject = user.getId().toString();
    	String clientId = ctx.client().getClientId();
    	Set<String> scopes = ctx.effectiveScopes();
    	
    	String access = tokens.createAccessToken(subject, clientId, scopes);
    	String refresh = tokens.createRefreshToken(subject, clientId, scopes);
    	
    	refreshTokens.save(new RefreshTokenRecord(
    			refresh,
    			subject,
    			clientId,
    			scopes,
    			System.currentTimeMillis() + REFRESH_TOKEN_TTL_MILLIS,
    			true));
    	
    	
    	Map<String, Object> out = new LinkedHashMap<>();
    	out.put("access_token", access);
    	out.put("token_type", "Bearer");
    	out.put("expires_in", 3600);
    	out.put("refresh_token", refresh);
    	
    	// RFC 6749 s.3.3: include "scope" in the response to indicate the granted scope (especially if defaulted or adjusted).
    	if (!scopes.isEmpty()) {
    		out.put("scope", String.join(" ", scopes));
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
