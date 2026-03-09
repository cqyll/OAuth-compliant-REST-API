package io.github.cqyll.todoapi.adapter.inbound.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.github.cqyll.todoapi.application.port.inbound.OAuthTokenUseCase;
import io.github.cqyll.todoapi.dto.OAuthTokenRequest;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * POST /login
 *
 * Input JSON:
 * {
 *   "client_id": "client_...",
 *   "client_secret": "optional_if_public",
 *   "email": "user@example.com",
 *   "password": "pass1234",
 *   "scope": "read write" // optional
 * }
 *
 * Behavior:
 * - Translates to OAuth password grant request
 * - Delegates to OAuthTokenUseCase (same pipeline as /oauth/token)
 * - Returns the OAuth token response map as JSON
 */
public final class LoginController implements HttpHandler {
	private static final ObjectMapper mapper = new ObjectMapper();
	
	private final OAuthTokenUseCase useCase;
	
	public LoginController(OAuthTokenUseCase tokenUseCase) {
		if (tokenUseCase == null) throw new IllegalArgumentException("tokenUseCase is required");
		this.useCase = tokenUseCase;
	}
	
	@Override
	public void handle(HttpExchange ex) throws IOException {
		// enforce HTTP method
		if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
			ex.getResponseHeaders().set("Allow", "POST");
			ex.sendResponseHeaders(405, -1);
			return;
		}
		
		try {
			// read raw request body bytes
			byte[] bytes = ex.getRequestBody().readAllBytes();
			if (bytes.length == 0) { throw OAuthError.invalidRequest("request body required"); }
			
			// decode bytes -> String (JSON text)
			String rawJson = new String(bytes, StandardCharsets.UTF_8);
			if (rawJson.isBlank()) { throw OAuthError.invalidRequest("request body required"); }
			
			// parse JSON -> LoginRequest DTO
			LoginRequest body = mapper.readValue(rawJson, LoginRequest.class);
			
			// validate required input fields
			// - client_id is required so OAuthTokenService can load the client and enforce rules
			String clientId = requireNonBlank(body.client_id, "client_id required");
			
			// resource owner credentials (OAuth password grant)
			String email = requireNonBlank(body.email, "email is required");
			String password = requireNonBlank(body.password, "password is required");
			
			// parse optional scope string -> Set<String>
			// service will compute effectiveScopes, i.e intersection of requested and allowedScopes 
			String scope = body.scope;
			
			// - client_secret optional here; only required by OAuthTokenService for confidential clients
			String clientSecret = body.client_secret;
			
			// build OAuthTokenRequest (DTO for OAuth layer)
			// this is needed since /login is just a user convenience endpoint. internally, it uses OAuth password grant.
			OAuthTokenRequest req = new OAuthTokenRequest(
					"password", // grant_type
					clientId,
					clientSecret,
					email, // username
					password,
					null, // code (not allowed for pw grant)
					null, // redirect_uri (not allowed for pw grant)
					null, // refresh_token (not allowed for pw grant)
					scope);
			
			// delegate to app layer
			Map<String, Object> out = useCase.token(req);
			
			// return response JSON (success)
			writeJson(ex, 200, out);
			
		} catch (OAuthError e) {
			// return OAuth errors
			writeJson(ex, e.getHttpStatus(), oAuthErrorBody(e));
		} catch (Exception e) {
			// this is just here to prevent leaking stack traces => will return server_error
			OAuthError err = OAuthError.serverError();
			writeJson(ex, err.getHttpStatus(), oAuthErrorBody(err));
		}
	}
	
	// helpers
	
	private static String requireNonBlank(String v, String msg) {
		if (v == null || v.isBlank()) throw OAuthError.invalidRequest(msg);
		return v.trim();
	}
	
	
	private static void writeJson(HttpExchange ex, int status, Object body) throws IOException {
		byte[] json = mapper.writeValueAsBytes(body);
		
		ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8"); // explicitly declares that response body is JSON w/ utf-8 encoding so clients parse it appropriately. UTF-8 charset ensures proper handling of any unicode characters
		ex.getResponseHeaders().set("Cache-control", "no-store"); // ensure clients do not cache request
		ex.getResponseHeaders().set("Pragma", "no-cache"); // for older HTTP clients that don't support "Cache-Control" header
		
		ex.sendResponseHeaders(status, json.length);
		try (OutputStream os = ex.getResponseBody()) {
			os.write(json);
		}
	}
	
	private static Map<String, Object> oAuthErrorBody(OAuthError e) {
		if (e.getDescription() != null && !e.getDescription().isBlank()) {
			return Map.of("error", e.getError(), "error_description", e.getDescription());
		}
		return Map.of("error", e.getError());
	}
	 
	// inbound JSON DTO
	public static final class LoginRequest {
		public String client_id;
		public String client_secret;
		
		public String email;
		public String password;
		public String scope; // optional, space-delimited
	}
}