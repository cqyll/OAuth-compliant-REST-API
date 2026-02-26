package io.github.cqyll.todoapi.application.service;

import io.github.cqyll.todoapi.application.port.outbound.PasswordHasherPort;
import io.github.cqyll.todoapi.application.port.outbound.TokenProviderPort;
import io.github.cqyll.todoapi.application.port.outbound.UserRepositoryPort;
import io.github.cqyll.todoapi.application.service.OAuthTokenService.GrantContext;
import io.github.cqyll.todoapi.domain.OAuthClient;
import io.github.cqyll.todoapi.domain.User;
import io.github.cqyll.todoapi.dto.OAuthTokenRequest;
import io.github.cqyll.todoapi.adapter.inbound.web.OAuthError;

import java.util.LinkedHashMap;
import java.util.Map;

public class PasswordGrantHandler implements TokenGrantHandler {
    private final UserRepositoryPort users;
    private final PasswordHasherPort hasher;
    private final TokenProviderPort tokens;

    public PasswordGrantHandler(UserRepositoryPort users, PasswordHasherPort hasher, TokenProviderPort tokens) {
        this.hasher = hasher;
        this.users = users;
        this.tokens = tokens;
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
    	
    	String access = tokens.createToken(user.getId().toString());
    	
    	Map<String, Object> out = new LinkedHashMap<>();
    	out.put("access_token", access);
    	out.put("token_type", "Bearer");
    	out.put("expires_in", 3600);
    	
    	// RFC 6749 s.3.3: include "scope" in the response to indicate the granted scope (especially if defaulted or adjusted).
    	if (!ctx.effectiveScopes().isEmpty()) {
    		out.put("scope", String.join(" ", ctx.effectiveScopes()));
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
