package io.github.cqyll.todoapi.application.port.outbound;

import io.github.cqyll.todoapi.domain.OAuthClient;

import java.util.Optional;

public interface OAuthClientRepositoryPort {
	void save(OAuthClient client);
	Optional<OAuthClient> findByClientId(String clientId);
	boolean existsByClientId(String clientId);
}
