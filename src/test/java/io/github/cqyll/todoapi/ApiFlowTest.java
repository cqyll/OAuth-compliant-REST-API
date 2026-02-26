// ApiFlowTest.java
package io.github.cqyll.todoapi;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.github.cqyll.todoapi.config.AppConfig;
import org.junit.jupiter.api.*;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ApiFlowTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private HttpServer server;
    private String baseUrl;

    private OAuthClientCreds passwordClient;

    // ✅ client_credentials client with allowed scopes
    private OAuthClientCreds ccClient;

    @BeforeAll
    void startServer() throws Exception {
        server = new AppConfig().createHttpServer();
        server.start();
        baseUrl = "http://localhost:" + server.getAddress().getPort();

        passwordClient = registerConfidentialClient(
                List.of("password"),
                List.of() // no scopes needed for password tests
        );

        ccClient = registerConfidentialClient(
                List.of("client_credentials"),
                List.of("todos.read", "todos.write")
        );
    }

    @AfterAll
    void stopServer() {
        if (server != null) server.stop(0);
    }

    @Test
    void usesEphemeralPort() {
        assertTrue(server.getAddress().getPort() > 0);
    }

    @Test
    void register_then_login() throws Exception {
        String email = uniqueEmail();
        String password = "Passw0rd!";

        String registrationToken = registerUser(email, "JUnit", password);
        assertLooksLikeToken(registrationToken);

        String loginToken = login(email, password);
        assertLooksLikeToken(loginToken);

        assertEquals(registrationToken, loginToken);
    }

    @Test
    void passwordGrant_withClientAuthViaHttpBasic_returnsAccessToken() throws Exception {
        String email = uniqueEmail();
        String password = "Passw0rd!";
        registerUser(email, "OAuth", password);

        HttpResponse<String> r = requestToken_passwordGrant_basicAuth(passwordClient, email, password);

        assertEquals(200, r.statusCode(), "Token request failed: HTTP " + r.statusCode() + " body=" + r.body());

        Map<String, Object> body = parseJsonObject(r.body());
        assertEquals("bearer", String.valueOf(body.get("token_type")).toLowerCase(Locale.ROOT));

        String accessToken = String.valueOf(body.get("access_token"));
        assertLooksLikeToken(accessToken);
    }

    @Test
    void tokenEndpoint_withInvalidClientSecret_returnsInvalidClient() throws Exception {
        String email = uniqueEmail();
        String password = "Passw0rd!";
        registerUser(email, "OAuth", password);

        OAuthClientCreds bad = new OAuthClientCreds(passwordClient.clientId, "wrong-secret");

        HttpResponse<String> r = requestToken_passwordGrant_basicAuth(bad, email, password);

        assertEquals(401, r.statusCode(), "Expected 401 invalid_client but got: " + r.statusCode() + " body=" + r.body());
        Map<String, Object> body = parseJsonObject(r.body());
        assertEquals("invalid_client", String.valueOf(body.get("error")));
        assertTrue(hasHeader(r.headers(), "WWW-Authenticate"), "Expected WWW-Authenticate header on 401");
    }

    // ✅ client_credentials: request subset scope succeeds
    @Test
    void clientCredentialsGrant_withAllowedScope_returnsAccessTokenAndScope() throws Exception {
        HttpResponse<String> r = requestToken_clientCredentials_basicAuth(ccClient, "todos.read");

        assertEquals(200, r.statusCode(), "Token request failed: HTTP " + r.statusCode() + " body=" + r.body());

        Map<String, Object> body = parseJsonObject(r.body());
        assertEquals("bearer", String.valueOf(body.get("token_type")).toLowerCase(Locale.ROOT));

        String accessToken = String.valueOf(body.get("access_token"));
        assertLooksLikeToken(accessToken);

        assertEquals("todos.read", String.valueOf(body.get("scope")));
    }

    // ✅ client_credentials: disallowed scope -> invalid_scope
    @Test
    void clientCredentialsGrant_withDisallowedScope_returnsInvalidScope() throws Exception {
        HttpResponse<String> r = requestToken_clientCredentials_basicAuth(ccClient, "admin");

        assertEquals(400, r.statusCode(), "Expected 400 invalid_scope but got: " + r.statusCode() + " body=" + r.body());

        Map<String, Object> body = parseJsonObject(r.body());
        assertEquals("invalid_scope", String.valueOf(body.get("error")));
    }

    // ✅ client_credentials: omitted scope -> defaults to all allowed (policy)
    @Test
    void clientCredentialsGrant_withoutScope_defaultsToAllAllowedScopes() throws Exception {
        HttpResponse<String> r = requestToken_clientCredentials_basicAuth(ccClient, null);

        assertEquals(200, r.statusCode(), "Token request failed: HTTP " + r.statusCode() + " body=" + r.body());

        Map<String, Object> body = parseJsonObject(r.body());
        String scope = String.valueOf(body.get("scope"));

        // Order is deterministic here because domain normalization preserves insertion order,
        // but we keep assertions flexible anyway.
        assertTrue(scope.contains("todos.read"));
        assertTrue(scope.contains("todos.write"));
    }

    // ✅ grant not allowed for this client -> unauthorized_client
    @Test
    void clientCredentialsGrant_withPasswordOnlyClient_returnsUnauthorizedClient() throws Exception {
        HttpResponse<String> r = requestToken_clientCredentials_basicAuth(passwordClient, "todos.read");

        assertEquals(400, r.statusCode(), "Expected 400 unauthorized_client but got: " + r.statusCode() + " body=" + r.body());

        Map<String, Object> body = parseJsonObject(r.body());
        assertEquals("unauthorized_client", String.valueOf(body.get("error")));
    }

    // ============================================================
    // Helpers
    // ============================================================

    private static String uniqueEmail() {
        return "user" + System.currentTimeMillis() + "@example.com";
    }

    private String login(String email, String password) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("email", email);
        payload.put("password", password);

        HttpResponse<String> r = sendJsonPost(baseUrl + "/login", payload);
        assertEquals(200, r.statusCode(), "Login failed: " + r.body());

        return extractToken(r.body());
    }

    private String registerUser(String email, String name, String password) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("email", email);
        payload.put("name", name);
        payload.put("password", password);

        HttpResponse<String> r = sendJsonPost(baseUrl + "/register", payload);

        if (r.statusCode() >= 400) {
            throw new RuntimeException("Register failed: HTTP " + r.statusCode() + " body=" + r.body());
        }

        return extractToken(r.body());
    }

    private OAuthClientCreds registerConfidentialClient(List<String> grantTypes, List<String> scopes) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("clientType", "confidential");
        payload.put("grantTypes", grantTypes);
        payload.put("redirectUris", List.of());
        payload.put("scopes", scopes);

        payload.put("clientName", "JUnit Client");
        payload.put("clientUri", "https://example.invalid/client");
        payload.put("logoUri", "https://example.invalid/logo.png");
        payload.put("policyUri", "https://example.invalid/privacy");
        payload.put("description", "Test client for ApiFlowTest");

        HttpResponse<String> r = sendJsonPost(baseUrl + "/oauth/clients", payload);
        assertEquals(201, r.statusCode(), "Client registration failed: " + r.body());

        Map<String, Object> body = parseJsonObject(r.body());
        String clientId = String.valueOf(body.get("clientId"));
        String clientSecret = String.valueOf(body.get("clientSecret"));

        assertNotNull(clientId);
        assertFalse(clientId.isBlank());
        assertNotNull(clientSecret);
        assertFalse(clientSecret.isBlank());

        return new OAuthClientCreds(clientId, clientSecret);
    }

    private HttpResponse<String> requestToken_passwordGrant_basicAuth(OAuthClientCreds c, String username, String password) throws Exception {
        String form = form(Map.of(
                "grant_type", "password",
                "username", username,
                "password", password
        ));

        String basic = Base64.getEncoder().encodeToString((c.clientId + ":" + c.clientSecret).getBytes(StandardCharsets.UTF_8));

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/oauth/token"))
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();

        return HTTP.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> requestToken_clientCredentials_basicAuth(OAuthClientCreds c, String scope) throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("grant_type", "client_credentials");
        if (scope != null && !scope.isBlank()) {
            params.put("scope", scope);
        }

        String basic = Base64.getEncoder().encodeToString((c.clientId + ":" + c.clientSecret).getBytes(StandardCharsets.UTF_8));

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/oauth/token"))
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form(params)))
                .build();

        return HTTP.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> sendJsonPost(String url, Object payload) throws Exception {
        String json = MAPPER.writeValueAsString(payload);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json; charset=utf-8")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        return HTTP.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private static String form(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (!first) sb.append('&');
            first = false;
            sb.append(enc(e.getKey())).append('=').append(enc(e.getValue()));
        }
        return sb.toString();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }

    private static String extractToken(String body) {
        if (body == null) return null;

        try {
            Map<String, Object> obj = MAPPER.readValue(body, new TypeReference<Map<String, Object>>() {});
            Object t = obj.get("token");
            if (t != null) return String.valueOf(t);
            Object at = obj.get("access_token");
            if (at != null) return String.valueOf(at);
        } catch (Exception ignored) { }

        try {
            return MAPPER.readValue(body, String.class);
        } catch (Exception ignored) { }

        return body;
    }

    private static Map<String, Object> parseJsonObject(String body) {
        try {
            return MAPPER.readValue(body, new TypeReference<Map<String, Object>>() {});
        } catch (Exception ignored) {
            return Map.of();
        }
    }

    private static void assertLooksLikeToken(String token) {
        assertNotNull(token);
        assertFalse(token.isBlank());
        assertTrue(token.length() >= 10);
        assertFalse(token.chars().anyMatch(Character::isWhitespace));
    }

    private static boolean hasHeader(HttpHeaders headers, String name) {
        Optional<String> v = headers.firstValue(name);
        return v.isPresent() && !v.get().isBlank();
    }

    private static final class OAuthClientCreds {
        final String clientId;
        final String clientSecret;

        OAuthClientCreds(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }
    }
}