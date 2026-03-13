package io.github.cqyll.todoapi.adapter.inbound.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;


import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;

public abstract class JsonPostController<Req, Res> implements HttpHandler {
	private static final ObjectMapper MAPPER = new ObjectMapper();
	
	// jackson cannot deserialize into type parameter `Req`. Needs real runtime class object, so we save the class token for the request type.
	private final Class<Req> requestType;
	
	protected JsonPostController(Class<Req> requestType) {
		if (requestType == null) throw new IllegalArgumentException("requestType is required");
		this.requestType = requestType;
	}
	
	@Override
	public final void handle(HttpExchange ex) throws IOException {
		if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
			ex.getResponseHeaders().set("Allow", "POST");
			ex.sendResponseHeaders(405, -1);
			return;
		}
		
		try {
			Req request = MAPPER.readValue(ex.getRequestBody(), requestType);
			Res response = handleRequest(request, ex);
			writeJson(ex, successStatus(), response);
		} catch (JsonProcessingException e) {
			writeJson(ex, 400, Map.of("error", "invalid_request", "error_description", "Invalid JSON"));
		} catch (IllegalArgumentException e) {
			writeJson(ex, 400, Map.of("error", "invalid_request", "error_description", e.getMessage()));
		}
	}
	
	
	// left HttpExchange here just for a escape hatch back into this class from callers...unused atm.
	protected abstract Res handleRequest(Req req, HttpExchange ex) throws IOException;
	
	protected static void writeJson(HttpExchange ex, int status, Object body) throws IOException {
		byte[] bytes = MAPPER.writeValueAsBytes(body);
		ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		ex.sendResponseHeaders(status, bytes.length);
		try (OutputStream os = ex.getResponseBody()) {
			os.write(bytes);
		}
	}
	
	protected int successStatus() {
		return 200;
	}
	
	protected static boolean isBlank(String v) {
		return v == null || v.isBlank();
	}
	
	
	/*
	 * current UserController
	 * 1. checks POST
	 * 2. parses JSON into a RegisterRequest dto
	 * 3. validates fields
	 * 4. calls registration service
	 * 5. builds RegisterResponse dto
	 * 6. writes JSON
	 * 7. catches bad JSON/ bad arguments
	 * 
	 * current ClientRegistrationController
	 * 1. checks POST
	 * 2. parses JSON into ClientRegistrationRequest dto
	 * 3. calls client registration service
	 * 4. writes JSON
	 * 5. catches bad arguments
	 * 
	 * -> should probably also catch bad json
	 * 
	 * Therefore, a generic base controller makes sense here.
	 * This abstraction should be a controller that accepts a JSON request body of type `Req`, and return a JSON response body of Type `Res`, and only supports POST
	 * 
	 */
	
	
	/*
	 * This class should only cover shared behaviors;
	 * 1. checks POST
	 * 2. deserialize JSON request body
	 * 3. serialize JSON response body
	 * 4. provide default invalid-request handling
	 * 5. delegate actual business logic to a subclass hook
	 * 
	 * It should not know anything about users, clients, registration, OAuth. It simply knows the request and response DTO types.
	 */
	
}

