package io.github.cqyll.todoapi.adapter.outbound.persistence;

import io.github.cqyll.todoapi.application.port.outbound.OAuthClientRepositoryPort;
import io.github.cqyll.todoapi.domain.OAuthClient;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class InMemoryOAuthClientAdapter implements OAuthClientRepositoryPort {
    private final Map<String, OAuthClient> byId = new HashMap<>();

    @Override
    public void save(OAuthClient client) {
        byId.put(client.getClientId(), client);
    }

    @Override
    public Optional<OAuthClient> findByClientId(String clientId) {
        if (clientId == null) return Optional.empty();
        return Optional.ofNullable(byId.get(clientId));
    }

    @Override
    public boolean existsByClientId(String clientId) {
        return clientId != null && byId.containsKey(clientId);
    }
}