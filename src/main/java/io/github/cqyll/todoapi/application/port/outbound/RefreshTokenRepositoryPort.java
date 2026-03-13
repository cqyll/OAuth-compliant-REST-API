package io.github.cqyll.todoapi.application.port.outbound;

import java.util.Optional;

public interface RefreshTokenRepositoryPort {
	Optional<RefreshTokenRecord> findByToken(String token);
	void save(RefreshTokenRecord record);
	void revoke(String token);
}
