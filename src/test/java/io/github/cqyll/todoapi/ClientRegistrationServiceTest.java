package io.github.cqyll.todoapi;

import io.github.cqyll.todoapi.application.port.outbound.OAuthClientRepositoryPort;
import io.github.cqyll.todoapi.application.port.outbound.PasswordHasherPort;
import io.github.cqyll.todoapi.application.service.ClientRegistrationService;
import io.github.cqyll.todoapi.domain.OAuthClient;
import io.github.cqyll.todoapi.dto.ClientRegistrationRequest;
import io.github.cqyll.todoapi.dto.ClientRegistrationResponse;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;


/**
 * Beginner-friendly service tests.
 *
 * Goal: prove ClientRegistrationService does the "OAuth developer portal" job:
 * - generates client_id always
 * - generates client_secret only for confidential clients
 * - hashes secret
 * - saves OAuthClient to repository
 */
public class ClientRegistrationServiceTest {
	
	@Test
	void register_confidential_returnsSecret_andSavesHashedSecret() {
		FakeClientRepo repo = new FakeClientRepo();
		FakeHasher hasher = new FakeHasher();
		
		ClientRegistrationService svc = new ClientRegistrationService(repo, hasher);
		
		ClientRegistrationRequest req = new ClientRegistrationRequest();
		req.setClientType("confidential");
		req.setGrantTypes(List.of("password"));
		req.setRedirectUris(List.of()); // no redirect uris needed for password grant
		
		ClientRegistrationResponse resp = svc.register(req);
		
		assertNotNull(resp.getClientId());
		assertFalse(resp.getClientId().isBlank());
		
		assertNotNull(resp.getClientSecret(), "Confidential client should receive a secret ONCE at creation.");
		assertFalse(resp.getClientSecret().isBlank());
		
		assertNotNull(repo.lastSaved);
		
		assertEquals(OAuthClient.ClientType.CONFIDENTIAL, repo.lastSaved.getClientType());
		
		assertTrue(repo.lastSaved.getClientSecretHash().startsWith("HASH("));
	}
	
	@Test
	void register_public_returnsNullSecret_andSavesPublicClient() {
		FakeClientRepo repo = new FakeClientRepo();
		FakeHasher hasher = new FakeHasher();
		
		ClientRegistrationService svc = new ClientRegistrationService(repo, hasher);
		ClientRegistrationRequest req = new ClientRegistrationRequest();
		req.setClientType("public");
		req.setGrantTypes(List.of("authorization_code"));
		req.setRedirectUris(List.of("https://example.com/callback"));
		
		ClientRegistrationResponse resp = svc.register(req);
		
		assertNotNull(resp.getClientId());
		assertNull(resp.getClientSecret(), "Public clients do not have a secret");
		
		assertNotNull(repo.lastSaved);
		assertEquals(OAuthClient.ClientType.PUBLIC, repo.lastSaved.getClientType());
		assertNull(repo.lastSaved.getClientSecretHash());
	}
	
	@Test
	void register_unknownGrantType_throws() {
		FakeClientRepo repo = new FakeClientRepo();
		FakeHasher hasher = new FakeHasher();
		
		ClientRegistrationService svc = new ClientRegistrationService(repo, hasher);
		ClientRegistrationRequest req = new ClientRegistrationRequest();
		req.setClientType("confidential");
		req.setGrantTypes(List.of("not_a_real_grant"));
		req.setRedirectUris(List.of());
		
		assertThrows(IllegalArgumentException.class, () -> svc.register(req));
		
	}
	
	// helpers & dummy adapters
	
	private static final class FakeClientRepo implements OAuthClientRepositoryPort {
		OAuthClient lastSaved;
		
		@Override
		public void save(OAuthClient client) {
			this.lastSaved = client;
		}
		
		@Override
		public Optional<OAuthClient> findByClientId(String clientId) {
			if (lastSaved != null && lastSaved.getClientId().equals(clientId) ) {
				return Optional.of(lastSaved);
			}
			return Optional.empty();
		}
		
		@Override
		public boolean existsByClientId(String clientId) {
			return lastSaved != null && lastSaved.getClientId().equals(clientId);
		}
	}
	
	private static final class FakeHasher implements PasswordHasherPort {
		@Override
		public String hash(String rawPassword) {
			return "HASH(" + rawPassword + ")";
		}
		
		@Override
		public boolean matches(String rawPassword, String hashedPassword) {
			return ("HASH(" + rawPassword + ")").equals(hashedPassword);
		}
		
	}
}
