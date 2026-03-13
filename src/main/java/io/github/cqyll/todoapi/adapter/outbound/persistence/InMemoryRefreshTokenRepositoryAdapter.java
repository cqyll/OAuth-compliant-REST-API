package io.github.cqyll.todoapi.adapter.outbound.persistence;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import io.github.cqyll.todoapi.application.port.outbound.RefreshTokenRecord;
import io.github.cqyll.todoapi.application.port.outbound.RefreshTokenRepositoryPort;

public class InMemoryRefreshTokenRepositoryAdapter implements RefreshTokenRepositoryPort {
	private final Map<String, RefreshTokenRecord> store = new ConcurrentHashMap<>();
	
	public Optional<RefreshTokenRecord> findByToken(String token) {
		return Optional.ofNullable(store.get(token));
	}
	
	public void save(RefreshTokenRecord record) {
		store.put(record.getToken(), record);
	}
	
	public void revoke(String token) {
		RefreshTokenRecord existing = store.get(token);
		if (existing != null) {
			store.put(token, existing.revoked());
		}
	}
}
