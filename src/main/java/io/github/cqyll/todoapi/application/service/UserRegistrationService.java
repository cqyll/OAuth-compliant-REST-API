package io.github.cqyll.todoapi.application.service;

import io.github.cqyll.todoapi.application.port.inbound.UserRegistrationUseCase;
import io.github.cqyll.todoapi.application.port.outbound.UserRepositoryPort;
import io.github.cqyll.todoapi.application.port.outbound.PasswordHasherPort;
import io.github.cqyll.todoapi.application.port.outbound.TokenProviderPort;
import io.github.cqyll.todoapi.domain.User;
import io.github.cqyll.todoapi.domain.Password;


public class UserRegistrationService implements UserRegistrationUseCase {
	private final UserRepositoryPort userRepository;
	private final PasswordHasherPort passwordHasher;

	public UserRegistrationService(
			UserRepositoryPort userRepository,
			PasswordHasherPort passwordHasher) {
		this.userRepository = userRepository;
		this.passwordHasher = passwordHasher;
	}

	@Override
	public User register(String email, String name, String rawPassword) {

		validateRegistrationPreconditions(email, rawPassword);

		String hash = passwordHasher.hash(rawPassword);
		Password password = Password.fromHash(hash);

		User user = User.createWithPassword(email, name, password);

		userRepository.save(user);

		return user;
	}

	private void validateRegistrationPreconditions(String email, String rawPassword) {
		validateEmailUniqueness(email);
		validatePasswordPolicy(rawPassword);
	} 

	private void validateEmailUniqueness(String email) {
		if (userRepository.existsByEmail(email)) {
			throw new IllegalArgumentException("Email already registered");
		}
	}

	private void validatePasswordPolicy(String rawPassword) {
		if (rawPassword.length() < 8) {
			throw new IllegalArgumentException("Password must be atleast 8 characters long.");
		}
	}


}