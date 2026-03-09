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

	
	/**
	 * Immutable per-call context passed to a grant handler.
	 * 
	 * <h2>Contract</h2>
	 * 
	 * <h3>Preconditions<h3>
	 * <ul>
	 * 	<li>P1: {@code client != null}.</li>
	 * 	<li>P2: {@code effectiveScopes != null} and is treated as immutable by consumers.</li>
	 * </ul>
	 * 
	 * <h3>Postconditions</h3>
	 * <ul>
	 * 	<li>Q1: {@code this.client == client} and {@code this.effectiveScopes == effectiveScopes}.</li>
	 * </ul>
	 * 
	 * <h3>Invariants</h3>
	 * <ul>
	 * 	<li>I1: References never change after construction (fields are {@code final}).</li>
	 * </ul>
	 */
	public static final class GrantContext {
		private final OAuthClient client;
		private final Set<String> effectiveScopes;
		
		public GrantContext(OAuthClient client, Set<String> effectiveScopes) {
			this.client = client;
			this.effectiveScopes = effectiveScopes;
		}
		
		 /**
         * <h2>Contract</h2>
         * <h3>Preconditions</h3>
         * <ul><li>P1: GrantContext invariants hold.</li></ul>
         * <h3>Postconditions</h3>
         * <ul><li>Q1: returns the same {@code client} reference captured at construction.</li></ul>
         * <h3>Invariants</h3>
         * <ul><li>I1: returned reference is stable across calls.</li></ul>
         */
		public OAuthClient client() { return client; }
		
		/**
         * <h2>Contract</h2>
         * <h3>Preconditions</h3>
         * <ul><li>P1: GrantContext invariants hold.</li></ul>
         * <h3>Postconditions</h3>
         * <ul><li>Q1: returns the same {@code effectiveScopes} reference captured at construction.</li></ul>
         * <h3>Invariants</h3>
         * <ul><li>I1: returned reference is stable across calls.</li></ul>
         */
		public Set<String> effectiveScopes() { return effectiveScopes; }
	}
	
	// GrantType -> handler map
	private final Map<OAuthClient.GrantType, TokenGrantHandler> handlers;
	// client repo and hasher
	private final OAuthClientRepositoryPort clientRepo;
	private final PasswordHasherPort hasher;
	
	/**
     * Constructs the token service and registers handlers by grant type.
     *
     * <h2>Contract</h2>
     *
     * <h3>Preconditions</h3>
     * <ul>
     *   <li>P1: {@code clientRepo != null}.</li>
     *   <li>P2: {@code hasher != null}.</li>
     *   <li>P3: {@code grantHandlers != null} (varargs array itself).</li>
     *   <li>P4: No two non-null handlers in {@code grantHandlers} return the same non-null {@code supports()} value.</li>
     * </ul>
     *
     * <h3>Postconditions</h3>
     * <ul>
     *   <li>Q1: {@code this.clientRepo == clientRepo} and {@code this.hasher == hasher}.</li>
     *   <li>Q2: {@code this.handlers} contains at most one handler per {@code GrantType}, based on {@code supports()}.</li>
     *   <li>Q3: {@code this.handlers} is unmodifiable (copied via {@code Map.copyOf}).</li>
     * </ul>
     *
     * <h3>Class invariants established</h3>
     * <ul>
     *   <li>I1: {@code handlers} is non-null and unmodifiable.</li>
     *   <li>I2: {@code handlers} keys are {@code OAuthClient.GrantType}; values are non-null handlers.</li>
     *   <li>I3: Uniqueness: at most one handler per {@code GrantType}.</li>
     *   <li>I4: {@code clientRepo} and {@code hasher} are non-null.</li>
     * </ul>
     *
     * <h3>Throws</h3>
     * <ul>
     *   <li>{@link IllegalStateException} if duplicate handlers exist for the same {@code GrantType}.</li>
     * </ul>
     */
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
	
	
	/**
     * Core OAuth token pipeline.
     *
     * <h2>Contract</h2>
     *
     * <h3>Preconditions (programmer-facing)</h3>
     * <ul>
     *   <li>P1: {@code req != null}.</li>
     *   <li>P2: Service class invariants hold (ports + handler registry wired correctly).</li>
     * </ul>
     *
     * <h3>Protocol/domain validation (expected runtime outcomes; not preconditions)</h3>
     * <ul>
     *   <li>R1: {@code grant_type} present/non-blank -> else {@code invalid_request}.</li>
     *   <li>R2: Client authentication succeeds -> else {@code invalid_client} (detail-suppressed).</li>
     *   <li>R3: {@code grant_type} supported -> else {@code unsupported_grant_type}.</li>
     *   <li>R4: Client authorized for grant -> else {@code unauthorized_client}.</li>
     *   <li>R5: Effective scopes resolve to a non-empty permitted set -> else {@code invalid_scope}.</li>
     *   <li>R6: Handler exists for grant -> else {@code unsupported_grant_type}.</li>
     * </ul>
     *
     * <h3>Method invariants</h3>
     * <ul>
     *   <li>M1 (Security gate): No handler is invoked unless authentication, grant validation,
     *       authorization, and scope resolution all succeed.</li>
     *   <li>M2: After {@code authenticateClient(req)} returns, {@code client != null} and is enabled;
     *       confidential secret (if applicable) has been verified or an {@code invalid_client} was thrown.</li>
     *   <li>M3: After {@code resolveEffectiveScopes(req, client)} returns, {@code effectiveScopes} is immutable,
     *       non-empty, and {@code effectiveScopes ⊆ client.allowedScopes}.</li>
     * </ul>
     *
     * <h3>Postconditions (on normal return)</h3>
     * <ul>
     *   <li>Q1: The returned map is exactly the handler output:
     *       {@code result == handler.handle(new GrantContext(client, effectiveScopes), req)}.</li>
     *   <li>Q2: A handler was invoked for the resolved {@code grant} and only after all gates passed.</li>
     * </ul>
     *
     * <h3>Throws</h3>
     * <ul>
     *   <li>{@link OAuthError} for OAuth protocol errors.</li>
     *   <li>Unchecked exceptions may indicate broken class invariants / wiring bugs.</li>
     * </ul>
     */
	public Map<String, Object> token(OAuthTokenRequest req) {
		
		// precondition check
		if (req == null) throw OAuthError.invalidRequest("request body is required");
		
		String grantRaw = requireNonBlankRequest(req.getGrantType(), "grant_type is required");
		
		// call client authentication helper
		OAuthClient client = authenticateClient(req);
		
		// parse and validate GrantType (protocol-level)
		OAuthClient.GrantType grant = OAuthClient.GrantType.fromString(grantRaw);
		
		if (grant == null) throw OAuthError.unsupportedGrantType("grant_type not supported");
		
		// client authorization
		if (!client.getAllowedGrantTypes().contains(grant)) {
			throw OAuthError.unauthorizedClient("client not authorized for this grant_type");
		}
		
		Set<String> effectiveScopes = resolveEffectiveScopes(req, client);
		TokenGrantHandler handler = handlers.get(grant);
		if (handler == null) throw OAuthError.unsupportedGrantType("grant_type not supported");
		
		return handler.handle(new GrantContext(client, effectiveScopes), req);
	}
	
	
	/**
     * Authenticates the OAuth client. Errors intentionally avoid leaking detail (OAuth guidance).
     *
     * <h2>Contract</h2>
     *
     * <h3>Preconditions</h3>
     * <ul>
     *   <li>P1: {@code req != null}.</li>
     *   <li>P2: Class invariants hold: {@code clientRepo != null}, and for confidential clients {@code hasher != null}.</li>
     * </ul>
     *
     * <h3>Method invariants</h3>
     * <ul>
     *   <li>M1: Any authentication failure is surfaced as {@code invalid_client("client authentication failed")}.</li>
     * </ul>
     *
     * <h3>Postconditions (on normal return)</h3>
     * <ul>
     *   <li>Q1: Returns a non-null {@code OAuthClient}.</li>
     *   <li>Q2: Returned client is enabled.</li>
     *   <li>Q3: If client is confidential, the presented secret matched the stored hash.</li>
     * </ul>
     *
     * <h3>Throws</h3>
     * <ul>
     *   <li>{@link OAuthError#invalidClient(String)} if authentication fails (including disabled client).</li>
     * </ul>
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
	
	/**
     * Resolves effective scopes for a request given the client policy.
     *
     * <h2>Contract</h2>
     *
     * <h3>Preconditions</h3>
     * <ul>
     *   <li>P1: {@code req != null}.</li>
     *   <li>P2: {@code client != null}.</li>
     *   <li>P3: {@code client.allowedScopes} is non-null and contains normalized scope tokens
     *       (assumed as a client/domain invariant).</li>
     * </ul>
     *
     * <h3>Method invariants</h3>
     * <ul>
     *   <li>M1: Normalization uses {@code OAuthClient.normalizeScopeTokens} and maps bad formats to {@code invalid_scope}.</li>
     *   <li>M2: If request scope omitted/blank, defaults to {@code client.allowedScopes} (copy).</li>
     *   <li>M3: If request scope present, effective scope is {@code requested ∩ allowed}.</li>
     * </ul>
     *
     * <h3>Postconditions (on normal return)</h3>
     * <ul>
     *   <li>Q1: Returns a non-null, unmodifiable set ({@code Set.copyOf}).</li>
     *   <li>Q2: Returned set is non-empty.</li>
     *   <li>Q3: Returned set is a subset of {@code client.allowedScopes}.</li>
     *   <li>Q4: If request scope omitted/blank, returned set equals {@code copyOf(client.allowedScopes)}.</li>
     * </ul>
     *
     * <h3>Throws</h3>
     * <ul>
     *   <li>{@code invalid_scope("invalid scope value")} if scope string cannot be normalized.</li>
     *   <li>{@code invalid_scope("requested scope is not allowed for this client")} if intersection is empty.</li>
     * </ul>
     */
	private Set<String> resolveEffectiveScopes(OAuthTokenRequest req, OAuthClient client) {
		final Set<String> requestedScopes;
		try {
			requestedScopes = OAuthClient.normalizeScopeTokens(req.getScope());
		} catch (IllegalArgumentException e) {
			throw OAuthError.invalidScope(e.getMessage());
		}
		
		// RFC 6749 Section 3.3; omitted/blank scope parameter -> return server defined default scopes
		if (requestedScopes.isEmpty()) return Set.copyOf(client.getAllowedScopes());
		
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
	
	/**
     * Enforces a required request parameter for protocol processing.
     *
     * <h2>Contract</h2>
     *
     * <h3>Preconditions</h3>
     * <ul>
     *   <li>P1: {@code msg != null} (error message constant).</li>
     * </ul>
     *
     * <h3>Postconditions (on normal return)</h3>
     * <ul>
     *   <li>Q1: Returns {@code v} (not trimmed) and guarantees it is non-null and not blank.</li>
     * </ul>
     *
     * <h3>Throws</h3>
     * <ul>
     *   <li>{@code invalid_request(msg)} if {@code v} is null or blank.</li>
     * </ul>
     */
	private static String requireNonBlankRequest(String v, String msg) {
		if (v == null || v.isBlank()) throw OAuthError.invalidRequest(msg);
		return v;
	}
	
	/**
     * Enforces a required client_id for client authentication.
     *
     * <h2>Contract</h2>
     *
     * <h3>Postconditions (on normal return)</h3>
     * <ul>
     *   <li>Q1: Returns {@code v} and guarantees it is non-null and not blank.</li>
     * </ul>
     *
     * <h3>Throws</h3>
     * <ul>
     *   <li>{@code invalid_client("client authentication failed")} if {@code v} is null or blank.</li>
     * </ul>
     */
	private static String requireNonBlankClient(String v) {
		if (v == null || v.isBlank()) throw OAuthError.invalidClient("client authentication failed");
		return v;
	}
	
	
}
