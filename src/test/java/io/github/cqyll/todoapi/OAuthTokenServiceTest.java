package io.github.cqyll.todoapi;

import io.github.cqyll.todoapi.adapter.inbound.web.OAuthError;
import io.github.cqyll.todoapi.application.port.outbound.OAuthClientRepositoryPort;
import io.github.cqyll.todoapi.application.port.outbound.PasswordHasherPort;
import io.github.cqyll.todoapi.application.port.outbound.TokenProviderPort;
import io.github.cqyll.todoapi.application.port.outbound.UserRepositoryPort;
import io.github.cqyll.todoapi.application.service.PasswordGrantHandler;
import io.github.cqyll.todoapi.application.service.TokenGrantHandler;
import io.github.cqyll.todoapi.application.service.OAuthTokenService;
import io.github.cqyll.todoapi.domain.OAuthClient;
import io.github.cqyll.todoapi.dto.OAuthTokenRequest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

final class OAuthTokenServiceTest {
	
	// EP0: Class invariants (ctor/registry)
	@Nested
	final class ClassInvariants {
		
		/*
		 * Promise: the service enforces the invariant "at most one handler per grant type".
		 */
		@Test
		void CTOR_REJECTSDUPLICATEHANDLERSFORSAMEGRANTTYPE() {
			TokenGrantHandler h1 = new SpyHandler(OAuthClient.GrantType.PASSWORD);
			TokenGrantHandler h2 = new SpyHandler(OAuthClient.GrantType.PASSWORD);
			
			assertThrows(IllegalStateException.class, () ->
					new OAuthTokenService(new InMemoryClientRepo(), new StubHasher(), h1, h2));
		}
	}
	
	// EP1 -- Failure partition: invalid_request
	@Nested
	final class InvalidRequest {
		
		/*
		 * Promise:
		 * 1. validated preconditions (request must exist)
		 * 2. method invariant: "no handler runs if request shape fails"
		 */
		@Test
		void token_invalidRequest_whenReqIsNull_andHandlerNotCalled() {
			SpyHandler spy = new SpyHandler(OAuthClient.GrantType.PASSWORD);
			OAuthTokenService svc = new OAuthTokenService(new InMemoryClientRepo(), new StubHasher(), spy);
			
			OAuthError e = assertThrows(OAuthError.class, () -> svc.token(null));
			assertEquals("invalid_request", e.getError());
			assertEquals(400, e.getHttpStatus());
			assertEquals(0, spy.calls);
		}
		
		/*
		 * Promise: validated precondition (grant_type is required)
		 */
		@Test
		void token_invalidRequest_whenGrantTypeMissing() {
			SpyHandler spy = new SpyHandler(OAuthClient.GrantType.PASSWORD);
			OAuthTokenService svc = new OAuthTokenService(new InMemoryClientRepo(), new StubHasher(), spy);
			
			OAuthTokenRequest req = new OAuthTokenRequest(
					null, "clientId", "clientSecret",
					"user", "pw",
					null, null, null,
					null
			);
			
			OAuthError e = assertThrows(OAuthError.class, () -> svc.token(req));
			assertEquals("invalid_request", e.getError());
			assertEquals(400, e.getHttpStatus());
			assertEquals("grant_type is required", e.getDescription());
			assertEquals(0, spy.calls);
		}
	}
	
	// EP2 -- Failure partition: invalid_client
	@Nested
	final class invalidClient {
		
		/*
		 * Promise: client authentication precondition is enforced (but collapsed to invalid_client)
		 */
		@Test
		void token_invalidClient_whenClientIdMissing() {
			SpyHandler spy = new SpyHandler(OAuthClient.GrantType.PASSWORD);
			OAuthTokenService svc = new OAuthTokenService(new InMemoryClientRepo(), new StubHasher(), spy);
			
			OAuthTokenRequest req = new OAuthTokenRequest(
					"password", null, "clientSecret",
					"user", "pw",
					null, null, null,
					null
			);
			
			OAuthError e = assertThrows(OAuthError.class, () -> svc.token(req));
			assertEquals("invalid_client", e.getError());
			assertEquals(401, e.getHttpStatus());
			assertEquals("client authentication failed", e.getDescription());
			assertEquals(0, spy.calls);
		}
		
		/*
		 * Promise: repository miss is surfaced as invalid_client
		 */
		@Test
		void token_invalidClient_whenClientNotFound() {
			SpyHandler spy = new SpyHandler(OAuthClient.GrantType.PASSWORD);
			OAuthTokenService svc = new OAuthTokenService(new InMemoryClientRepo(), new StubHasher(), spy);
			
			OAuthTokenRequest req = new OAuthTokenRequest(
					"password", "missing", null,
					"user", "pw",
					null, null, null,
					null
			);
			
			OAuthError e = assertThrows(OAuthError.class, () -> svc.token(req));
			assertEquals("invalid_client", e.getError());
			assertEquals(401, e.getHttpStatus());
			assertEquals("client authentication failed", e.getDescription());
			assertEquals(0, spy.calls);
		}
		
		/*
		 * Promise: authentication failures collapse to the same OAuth error.
		 */
		@Test
		void token_invalidClient_collapseDifferentAuthFailures() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
			repo.save(confidentialClient(
					"c1",
					"HASH(correct)",
					EnumSet.of(OAuthClient.GrantType.PASSWORD),
					List.of("read"),
					true
			));
			
			OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), new SpyHandler(OAuthClient.GrantType.PASSWORD));
			
			
			// cause: unknown client
			OAuthTokenRequest unknown = new OAuthTokenRequest("password", "nope", "x", "user", "pw", null, null, null, null);
			OAuthError e1 = assertThrows(OAuthError.class, () -> svc.token(unknown));
			
			// cause: wrong secret
			OAuthTokenRequest wrongSecret = new OAuthTokenRequest("password", "c1", "wrong", "user", "pw", null, null, null, null);
			OAuthError e2 = assertThrows(OAuthError.class, () -> svc.token(wrongSecret));
			
			assertEquals("invalid_client", e1.getError());
			assertEquals("invalid_client", e2.getError());
			
			assertEquals(e1.getDescription(), e2.getDescription()); // same message
		}
	}
	
	// EP3 -- Failure partition: unsupported_grant_type
	@Nested
	final class unsupportedGrantType {
		
		/*
		 * Promise: protocol-level validation of grant type
		 */
		@Test
		void token_unsupportedGrantType_whenGrantNotRecognized() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
		    repo.save(publicClient("p1", EnumSet.of(OAuthClient.GrantType.PASSWORD), List.of("read"), true));

		    OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), new SpyHandler(OAuthClient.GrantType.PASSWORD));

		    OAuthTokenRequest req = new OAuthTokenRequest(
		            "banana", "p1", null,
		            "u", "p",
		            null, null, null,
		            null
		    );
		    
		    OAuthError e = assertThrows(OAuthError.class, () -> svc.token(req));
		    assertEquals("unsupported_grant_type", e.getError());
		}
		
		/*
		 * Promise: service rejects valid grant if it cannot dispatch to a handler
		 */
		@Test
		void token_unsupportedGrantType_whenNoHandlerRegisteredForValidGrant() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
		    repo.save(publicClient("p1", EnumSet.of(OAuthClient.GrantType.PASSWORD), List.of("read"), true));

		    OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), new SpyHandler(OAuthClient.GrantType.CLIENT_CREDENTIALS));

		    OAuthTokenRequest req = new OAuthTokenRequest(
		            "password", "p1", null,
		            "u", "p",
		            null, null, null,
		            null
		    );
		    
		    OAuthError e = assertThrows(OAuthError.class, () -> svc.token(req));
		    assertEquals("unsupported_grant_type", e.getError());
		}
	}
	
	// EP4 -- Failure partition: unauthorized_client
	@Nested
	final class unauthorizedClient {
		
		
		/*
		 * Promise: client authorization gate (client authenticated but not allowed that grant)
		 */
		@Test
		void token_unauthorizedClient_whenClientNotAllowedGrant() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
			repo.save(publicClient("p1", EnumSet.of(OAuthClient.GrantType.CLIENT_CREDENTIALS), List.of("read"), true));
			
			OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), new SpyHandler(OAuthClient.GrantType.PASSWORD));
			
			OAuthTokenRequest req = new OAuthTokenRequest(
					"password",
					"p1",
					null,
					"u",
					"p",
					null, null, null,
					null
			);
			
			OAuthError e = assertThrows(OAuthError.class, () -> svc.token(req));
			assertEquals("unauthorized_client", e.getError());	
		}
	}
	
	// EP5 -- Failure partition: invalid_scope
	@Nested
	final class invalidScope {
		/*
		 * Promise: scope syntax validation 
		 */
		@Test
		void token_invalidScope_whenScopeSyntaxInvalid() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
			repo.save(publicClient("p1", EnumSet.of(OAuthClient.GrantType.PASSWORD), List.of("read", "write"), true));
			
			OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), new SpyHandler(OAuthClient.GrantType.CLIENT_CREDENTIALS));
			
			String offending = "!!";
			String scope = "read " + offending;
			
			OAuthTokenRequest req = new OAuthTokenRequest(
					"password",
					"p1",
					null,
					"user",
					"pw",
					null, null, null,
					scope
			);
			
			OAuthError e = assertThrows(OAuthError.class, () -> svc.token(req));
			assertEquals("invalid_scope", e.getError());
			assertEquals(400, e.getHttpStatus());
			assertEquals("invalid scope token: " + offending, e.getDescription());
		}
		
		/*
		 * Promise: disallowed scopes (empty intersection) is rejected
		 */
		@Test
		void token_invalidScope_whenAllRequestedScopesDisallowed() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
			repo.save(publicClient("p1", EnumSet.of(OAuthClient.GrantType.PASSWORD), List.of("read"), true));
			
			OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), new SpyHandler(OAuthClient.GrantType.PASSWORD));
			
			OAuthTokenRequest req = new OAuthTokenRequest("password", "p1", null, "u", "p", null, null, null, "admin");
			
			OAuthError e = assertThrows(OAuthError.class, () -> svc.token(req));
			assertEquals("invalid_scope", e.getError());
			assertEquals("requested scope is not allowed for this client", e.getDescription());
		}
	}
	
	// EP6 -- Sucess Partition: dispatch + return value + context correctness
	@Nested
	final class successDispatch {
		/*
		 * Promise:
		 * 
		 * Postconditions on success include;
		 * 1. handler is invoked exactly once
		 * 2. correct handler (by grant type) is used
		 * 3. handler receives authenticated client
		 * 4. handler receives effectiveScopes computed by service
		 * 5. service returns handler output 
		 */
		@Test
		void token_success_dispatchesToCorrectHandler_andReturnsHandlerOutput_andPassesCtx() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
			
			OAuthClient client = publicClient("p1", EnumSet.of(OAuthClient.GrantType.PASSWORD),
					List.of("read", "write"),
					true);
			repo.save(client);
			
			SpyHandler spy = new SpyHandler(OAuthClient.GrantType.PASSWORD);
			spy.nextResponse = Map.of("access_token", "T", "token_type", "Bearer");
			
			OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), spy);
			
			OAuthTokenRequest req = new OAuthTokenRequest("password", "p1", null, "user", "pw", null, null, null, "read");
			
			Map<String, Object> out = svc.token(req);
			
			// Postcondition: exactly one handler invocation
	        assertEquals(1, spy.calls);

	        // Postcondition: handler got the same request object
	        assertSame(req, spy.lastReq);

	        // Postcondition: handler got the authenticated client
	        assertSame(client, spy.lastCtx.client());

	        // Postcondition: handler got effective scopes computed by service
	        assertEquals(Set.of("read"), spy.lastCtx.effectiveScopes());

	        // Postcondition: service returns the handler output
	        assertEquals("T", out.get("access_token"));
	        assertEquals("Bearer", out.get("token_type"));
		}
		
		/*
		 * if the service registers multiple handlers, select the correct one --> no accidental calls to the wrong handler
		 */
		@Test
		void token_success_multipleHandlersRegistered() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
	        repo.save(publicClient("p1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of("read"),
	                true));

	        SpyHandler password = new SpyHandler(OAuthClient.GrantType.PASSWORD);
	        SpyHandler clientCreds = new SpyHandler(OAuthClient.GrantType.CLIENT_CREDENTIALS);

	        OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), password, clientCreds);

	        OAuthTokenRequest req = new OAuthTokenRequest(
	                "password", "p1", null,
	                "u", "p",
	                null, null, null,
	                "read"
	        );

	        svc.token(req);

	        assertEquals(1, password.calls);
	        assertEquals(0, clientCreds.calls);
		}
	}
	
	// EP7 -- Success partition: scope parameter omitted
	@Nested
	final class successDefaultScopes {
		/*
		 * if scope parameter is blank/omitted then effectiveScopes == client.allowedScopes
		 */
		
		@Test
		void token_success_defaultsToClientAllowedScopes() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
			
			OAuthClient client = publicClient("p1", EnumSet.of(OAuthClient.GrantType.PASSWORD), List.of("read", "write"), true);
			repo.save(client);
			
			SpyHandler spy = new SpyHandler(OAuthClient.GrantType.PASSWORD);
			
			OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), spy);
			
			OAuthTokenRequest req = new OAuthTokenRequest("password", "p1", null, "user", "pw", null, null, null, "  ");

			svc.token(req);
			
			assertEquals(Set.of("read", "write"), spy.lastCtx.effectiveScopes());
		}
	}
	
	// EP8 -- Success partition: partial-grant policy = intersection
	@Nested
	final class successPartialScopes {
		
		/*
		 * This equivalence class represents scopes with a mix of allowed and disallowed tokens -> non-empty intersection
		 * POSTCONDITION: effectiveScopes = requested AND allowed when request scope is present
		 */
		@Test
		void token_success_partialScopes() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
			
			OAuthClient client = publicClient("p1", EnumSet.of(OAuthClient.GrantType.PASSWORD), List.of("read"), true);
			repo.save(client);
			
			SpyHandler spy = new SpyHandler(OAuthClient.GrantType.PASSWORD);
			
			OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), spy);
			
			OAuthTokenRequest req = new OAuthTokenRequest("password", "p1", null, "user", "pw", null, null, null, "read admin");

			svc.token(req);
			
			assertEquals(Set.of("read"), spy.lastCtx.effectiveScopes());
		}
	}
	
	@Nested
	final class SuccessHandlerSelection {
		
		@Test
		void token_success_routesToCorrectHandler() {
			InMemoryClientRepo repo = new InMemoryClientRepo();
			
			OAuthClient client = publicClient("p1",
					EnumSet.of(OAuthClient.GrantType.PASSWORD, OAuthClient.GrantType.CLIENT_CREDENTIALS),
					List.of("read"),
					true);
			
			repo.save(client);
			
			SpyHandler password = new SpyHandler(OAuthClient.GrantType.PASSWORD);
			SpyHandler clientCreds = new SpyHandler(OAuthClient.GrantType.CLIENT_CREDENTIALS);

			OAuthTokenService svc = new OAuthTokenService(repo, new StubHasher(), password, clientCreds);
	
	        OAuthTokenRequest r1 = new OAuthTokenRequest(
	                "password", "p1", null,
	                "u", "p",
	                null, null, null,
	                "read"
	        );
	        svc.token(r1);

	        assertEquals(1, password.calls);
	        assertEquals(0, clientCreds.calls);
	        
	        assertNotEquals(password.calls, clientCreds.calls);

	        OAuthTokenRequest r2 = new OAuthTokenRequest(
	                "client_credentials", "p1", null,
	                null, null,
	                null, null, null,
	                "read"
	        );
	        svc.token(r2);
	        
	        assertEquals(1, password.calls);
	        assertEquals(1, clientCreds.calls);

	        assertEquals(password.calls, clientCreds.calls);
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	// Test doubles
	
	static final class InMemoryClientRepo implements OAuthClientRepositoryPort {
		private final Map<String, OAuthClient> byId = new HashMap<>();
		
		@Override public void save(OAuthClient client) {
			if (client == null) throw new IllegalArgumentException("client must not be null");
			byId.put(client.getClientId(), client);
		}
		
		@Override public Optional<OAuthClient> findByClientId(String clientId) {
			if (clientId == null) return Optional.empty();
			return Optional.ofNullable(byId.get(clientId));
		}
		
		@Override public boolean existsByClientId(String clientId) {
			if (clientId == null) return false;
			return byId.containsKey(clientId);
		}
		
	}
	
	static final class StubHasher implements PasswordHasherPort {
		@Override public String hash(String rawPassword) { return "HASH(" + rawPassword + ")"; }
		@Override public boolean matches(String rawPassword, String hashedPassword) {
			return ("HASH(" + rawPassword + ")").equals(hashedPassword);
		}
	}
	
	static final class SpyHandler implements TokenGrantHandler {
		private final OAuthClient.GrantType supports;
		int calls;
		OAuthTokenService.GrantContext lastCtx;
		OAuthTokenRequest lastReq;
		
		Map<String, Object> nextResponse = Map.of("access_token", "X", "token_type", "Bearer");
		
		SpyHandler(OAuthClient.GrantType supports) { this.supports = supports; }
		
		@Override public OAuthClient.GrantType supports() { return supports; }
		
		@Override public Map<String, Object> handle(OAuthTokenService.GrantContext ctx, OAuthTokenRequest req) {
			calls++;
			lastCtx = ctx;
			lastReq = req;
			return nextResponse;
		}
	}
	
	// helpers
	private static OAuthClient publicClient(String id, Set<OAuthClient.GrantType> grants, List<String> scopes, boolean enabled) {
		return OAuthClient.createPublic(id, grants, List.of(), scopes, OAuthClient.Metadata.empty(), enabled, 1L);
	}
	
	private static OAuthClient confidentialClient(String id, String secretHash, Set<OAuthClient.GrantType> grants, List<String> scopes, boolean enabled) {
		return OAuthClient.createConfidential(id, secretHash, grants, List.of(), scopes, OAuthClient.Metadata.empty(), enabled, 1L);
	}	
	
}
