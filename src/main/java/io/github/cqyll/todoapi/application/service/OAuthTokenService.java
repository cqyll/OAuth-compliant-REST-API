package io.github.cqyll.todoapi.application.service;

import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import io.github.cqyll.todoapi.adapter.inbound.web.OAuthError;
import io.github.cqyll.todoapi.application.port.inbound.OAuthTokenUseCase;
import io.github.cqyll.todoapi.application.port.outbound.OAuthClientRepositoryPort;
import io.github.cqyll.todoapi.application.port.outbound.PasswordHasherPort;
import io.github.cqyll.todoapi.domain.OAuthClient;
import io.github.cqyll.todoapi.dto.OAuthTokenRequest;


public class OAuthTokenService implements OAuthTokenUseCase {

	public static final class GrantContext {
		private final OAuthClient client;
		private final Set<String> effectiveScopes;
		
		public GrantContext(OAuthClient client, Set<String> effectiveScopes) {
			this.client = client;
			this.effectiveScopes = effectiveScopes;
		}
		
		public OAuthClient client() { return client; }
		public Set<String> effectiveScopes() { return effectiveScopes; }
	}
	
	// GrantType -> handler map
	private final Map<OAuthClient.GrantType, TokenGrantHandler> handlers;
	// client repo and hasher
	private final OAuthClientRepositoryPort clientRepo;
	private final PasswordHasherPort hasher;
	
	
	public OAuthTokenService(
			OAuthClientRepositoryPort clientRepo,
			PasswordHasherPort hasher,
			TokenGrantHandler...grantHandlers) {
		this.clientRepo = clientRepo;
		this.hasher = hasher;
		
		EnumMap<OAuthClient.GrantType, TokenGrantHandler> map = new EnumMap<>(OAuthClient.GrantType.class);
		
		for (TokenGrantHandler h : grantHandlers) {
			if (h == null) continue;
			OAuthClient.GrantType gt = h.supports();
			if (gt == null) continue;
		
			TokenGrantHandler prev = map.putIfAbsent(gt, h);
			if (prev != null) {
				throw new IllegalStateException("Duplicate handler for " + gt);
			}
		}
		this.handlers = Map.copyOf(map);
	}
	
	public Map<String, Object> token(OAuthTokenRequest req) {
		
		// request shape validation
		if (req == null) throw OAuthError.invalidRequest("request body is required");
		
		String grantRaw = requireNonBlankRequest(req.getGrantType(), "grant_type is required");
		
		// call client authentication helper
		OAuthClient client = authenticateClient(req);
		
		// parse and validate GrantType (protocol-level)
		OAuthClient.GrantType grant = OAuthClient.GrantType.fromString(grantRaw);
		
		if (grant == null) throw OAuthError.unsupportedGrantType("grant_type not supported");
		
		// client authentication
		if (!client.getAllowedGrantTypes().contains(grant)) {
			throw OAuthError.unauthorizedClient("client not authorized for this grant_type");
		}
		
		Set<String> effectiveScopes = resolveEffectiveScopes(req, client);
		TokenGrantHandler handler = handlers.get(grant);
		if (handler == null) throw OAuthError.unsupportedGrantType("grant_type not supported");
		
		return handler.handle(new GrantContext(client, effectiveScopes), req);
	}
	
	
	/**
	 * this helper authenticates client and avoids leaking details in error messages -- as per OAuth spec.
	 * @param req
	 * @return
	 */
	private OAuthClient authenticateClient(OAuthTokenRequest req) {
		String clientId = requireNonBlankClient(req.getClientId());
		
		OAuthClient client = clientRepo.findByClientId(clientId)
				.orElseThrow(() -> OAuthError.invalidClient("client authentication failed"));
		
		if (!client.isEnabled()) { throw OAuthError.invalidClient("client authentication failed"); }
		
		if (client.getClientType() == OAuthClient.ClientType.CONFIDENTIAL) {
			String secret = req.getClientSecret();
			if (secret == null || secret.isBlank()) {
				throw OAuthError.invalidClient("client authentication failed");
			}
			
			String hash = client.getClientSecretHash();
			if (hash == null || hash.isBlank() || !hasher.matches(secret, hash)) {
				throw OAuthError.invalidClient("client authentication failed");
			}
		}
		return client;
	}
	
	
	private Set<String> resolveEffectiveScopes(OAuthTokenRequest req, OAuthClient client) {
		final Set<String> requestedScopes;
		try {
			requestedScopes = OAuthClient.normalizeScopeTokens(req.getScope());
		} catch (IllegalArgumentException e) {
			throw OAuthError.invalidScope("invalid scope value");
		}
		
		// RFC 6749 Section 3.3; omitted/blank scope parameter -> return server defined default scopes
		if (requestedScopes.isEmpty()) return client.getAllowedScopes();
		
		// partial grant policy: granted = requested \cap allowed
		Set<String> granted = new LinkedHashSet<>(requestedScopes);
		granted.retainAll(client.getAllowedScopes());
		
		// nothing requested is permitted
		if (granted.isEmpty()) {
			throw OAuthError.invalidScope("requested scope is not allowed for this client");
		}
		
		
		// Collections.unmodifiableSet(granted) would return a view, use Set.copyOf() instead
		return Set.copyOf(granted);
		
	}
	
	private static String requireNonBlankRequest(String v, String msg) {
		if (v == null || v.isBlank()) throw OAuthError.invalidRequest(msg);
		return v;
	}
	
	private static String requireNonBlankClient(String v) {
		if (v == null || v.isBlank()) throw OAuthError.invalidClient("client authentication failed");
		return v;
	}
	
	
}
