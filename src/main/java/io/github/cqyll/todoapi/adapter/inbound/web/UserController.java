package io.github.cqyll.todoapi.adapter.inbound.web;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.github.cqyll.todoapi.application.port.inbound.UserRegistrationUseCase;
import io.github.cqyll.todoapi.application.service.UserRegistrationService;
import io.github.cqyll.todoapi.dto.RegisterRequest;

public class UserController implements HttpHandler {

	private final UserRegistrationUseCase registrationService;
	private static final ObjectMapper mapper = new ObjectMapper();


	public UserController(UserRegistrationUseCase registrationService) {
		this.registrationService = registrationService;
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		if (!"POST".equals(exchange.getRequestMethod())) {
			exchange.sendResponseHeaders(405, -1);
			return;
		}
		RegisterRequest request;

		try (InputStream is = exchange.getRequestBody()) {
			request = mapper.readValue(is, RegisterRequest.class);
		} catch (Exception e) {
			sendResponse(exchange, 400, "Invalid JSON"); // bad request
			return;
		}

		// transport level validation
		if (request.getEmail() == null || request.getName() == null || request.getPassword() == null) {
			sendResponse(exchange, 400, "Missing fields"); // bad request
			return;
		}

		try {
			String issueValidToken = registrationService.register(
					request.getEmail(),
					request.getName(),
					request.getPassword());
			sendResponse(exchange, 201, issueValidToken);
		} catch (IllegalArgumentException e) {
			sendResponse(exchange, 409, e.getMessage()); 
		}
	}

	private void sendResponse(HttpExchange exchange, int status, Object body) 
			throws IOException {
		byte[] bytes = mapper.writeValueAsBytes(body);

		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		exchange.sendResponseHeaders(status, bytes.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(bytes);
		}
	}
}
