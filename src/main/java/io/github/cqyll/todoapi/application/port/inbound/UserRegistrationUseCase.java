package io.github.cqyll.todoapi.application.port.inbound;

import io.github.cqyll.todoapi.domain.User;

public interface UserRegistrationUseCase {
	User register(String email, String name, String rawPassword);
}
