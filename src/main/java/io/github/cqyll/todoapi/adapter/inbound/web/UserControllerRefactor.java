package io.github.cqyll.todoapi.adapter.inbound.web;

import com.sun.net.httpserver.HttpExchange;

import io.github.cqyll.todoapi.application.port.inbound.UserRegistrationUseCase;
import io.github.cqyll.todoapi.domain.User;
import io.github.cqyll.todoapi.dto.RegisterRequest;
import io.github.cqyll.todoapi.dto.RegisterResponse;

public class UserControllerRefactor extends JsonPostController<RegisterRequest, RegisterResponse> {
	private final UserRegistrationUseCase registrationService;
	
	public UserControllerRefactor(UserRegistrationUseCase registrationService) {
		super(RegisterRequest.class);
		this.registrationService = registrationService;
	}
	
	@Override
	protected int successStatus() {
		return 201;
	}
	
	@Override
	protected RegisterResponse handleRequest(RegisterRequest req, HttpExchange ex) {
		if (req == null
				|| isBlank(req.getEmail())
				|| isBlank(req.getName())
				|| isBlank(req.getPassword())) {
			throw new IllegalArgumentException("Missing fields");
		}
		
		User user = registrationService.register(req.getEmail(), req.getName(), req.getPassword());
		
		return new RegisterResponse(
				user.getId().toString(),
				user.getEmail(),
				user.getName(),
				user.isActive(),
				user.isEmailVerified());
	}
}
