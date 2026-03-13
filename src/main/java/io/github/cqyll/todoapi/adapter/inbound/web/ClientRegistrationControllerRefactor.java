package io.github.cqyll.todoapi.adapter.inbound.web;

import com.sun.net.httpserver.HttpExchange;

import io.github.cqyll.todoapi.application.port.inbound.ClientRegistrationUseCase;
import io.github.cqyll.todoapi.dto.ClientRegistrationRequest;
import io.github.cqyll.todoapi.dto.ClientRegistrationResponse;

public class ClientRegistrationControllerRefactor extends JsonPostController<ClientRegistrationRequest, ClientRegistrationResponse> {
	private final ClientRegistrationUseCase clientRegistrationService;
	
	public ClientRegistrationControllerRefactor(ClientRegistrationUseCase clientRegistrationService) {
		super(ClientRegistrationRequest.class);
		this.clientRegistrationService = clientRegistrationService;
	}
	
	public final ClientRegistrationResponse handleRequest(ClientRegistrationRequest req, HttpExchange ex) {
		return clientRegistrationService.register(req);
	}
	
	@Override
	protected int successStatus() {
		return 201;
	}
}
