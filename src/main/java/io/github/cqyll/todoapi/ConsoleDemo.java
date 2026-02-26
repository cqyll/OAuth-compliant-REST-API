package io.github.cqyll.todoapi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.github.cqyll.todoapi.config.AppConfig;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Console demo that:
 *  1) starts your HttpServer (AppConfig)
 *  2) hits /users, /clients, /oauth/token, /login (optional)
 *  3) prints detailed request/response + "which file handles what" notes
 *
 * Run:  java ConsoleDemo
 */
public final class ConsoleDemo {

    private static final ObjectMapper om = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        int port = 8080;
        String base = "http://localhost:" + port;

        // ========== 0) Start server ==========
        banner("BOOT");
        System.out.println("AppConfig.createServer(" + port + ")");
        System.out.println("  -> wiring ports/adapters + controllers");
        System.out.println("  -> creates HttpServer contexts:");
        System.out.println("     /users   -> UserController");
        System.out.println("     /clients -> ClientRegistrationController");
        System.out.println("     /oauth/token -> OAuthController -> OAuthTokenService -> GrantHandler");
        System.out.println("     /login   -> (your LoginController; recommended: wrapper around OAuth password grant)");
        System.out.println();

        HttpServer server = AppConfig.createServer(port);
        server.start();
        System.out.println("Server started at " + base);
        System.out.println();

        HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();

        try {
            // ========== 1) Register a user ==========
            banner("1) POST /users (register user)");
            System.out.println("Handled by:");
            System.out.println("  UserController  -> parses JSON RegisterRequest");
            System.out.println("  UserRegistrationService -> creates user + hashes password + saves via UserRepositoryPort");
            System.out.println("  TokenProviderPort -> creates token (UserController currently returns a token string body)");
            System.out.println();

            String registerBody = """
                    {
                      "name": "Mahd",
                      "email": "mahd@example.com",
                      "password": "pass1234"
                    }
                    """;

            httpJson(http, "POST", base + "/users", registerBody);

            // ========== 2) Register a PUBLIC client for password grant ==========
            // IMPORTANT: OAuthTokenService.authenticateClient() requires client_id ALWAYS.
            // So password grant needs a client_id. If client is PUBLIC, no secret required.
            banner("2) POST /clients (create PUBLIC client for password grant)");
            System.out.println("Handled by:");
            System.out.println("  ClientRegistrationController -> parses JSON ClientRegistrationRequest");
            System.out.println("  ClientRegistrationService -> validates + generates client_id; hashes secret if confidential; saves");
            System.out.println();
            System.out.println("Why do we create this?");
            System.out.println("  OAuthTokenService.authenticateClient() requires client_id for ALL grants.");
            System.out.println("  PUBLIC client => no client_secret required.");
            System.out.println();

            String publicClientReq = """
                    {
                      "clientType": "public",
                      "grantTypes": ["password"],
                      "redirectUris": [],
                      "scopes": ["read", "write"],
                      "clientName": "Login UI"
                    }
                    """;

            JsonNode publicClientResp = httpJson(http, "POST", base + "/clients", publicClientReq);
            String publicClientId = publicClientResp.get("clientId").asText();

            System.out.println();
            System.out.println("Saved for later:");
            System.out.println("  publicClientId = " + publicClientId);
            System.out.println();

            // ========== 3) Call OAuth password grant at /oauth/token ==========
            banner("3) POST /oauth/token (password grant) [OAuth spec endpoint]");
            System.out.println("Handled by:");
            System.out.println("  OAuthController -> parses form-urlencoded + Basic auth header (client creds) into OAuthTokenRequest DTO");
            System.out.println("  OAuthTokenService -> authenticates client_id (and secret if confidential), checks allowed grants/scopes");
            System.out.println("  PasswordGrantHandler -> validates username/password, issues access token, returns Map");
            System.out.println();
            System.out.println("Expected Map response (from PasswordGrantHandler):");
            System.out.println("  {");
            System.out.println("    access_token: \"...\",");
            System.out.println("    token_type: \"Bearer\",");
            System.out.println("    expires_in: 3600,");
            System.out.println("    scope: \"read write\"   (only if effectiveScopes is non-empty)");
            System.out.println("  }");
            System.out.println();

            String tokenPasswordForm = form(Map.of(
                    "grant_type", "password",
                    "client_id", publicClientId,
                    "username", "mahd@example.com",
                    "password", "pass1234",
                    "scope", "read write"
            ));

            httpForm(http, base + "/oauth/token", tokenPasswordForm, null);

            // ========== 4) Register a CONFIDENTIAL client for client_credentials ==========
            banner("4) POST /clients (create CONFIDENTIAL client for client_credentials)");
            System.out.println("Handled by:");
            System.out.println("  ClientRegistrationController -> JSON");
            System.out.println("  ClientRegistrationService -> hashes and stores client_secret hash");
            System.out.println();
            System.out.println("Why confidential here?");
            System.out.println("  client_credentials is meant for clients (not humans). Confidential clients authenticate with secret.");
            System.out.println();

            String confidentialClientReq = """
                    {
                      "clientType": "confidential",
                      "grantTypes": ["client_credentials"],
                      "redirectUris": [],
                      "scopes": ["service.read", "service.write"],
                      "clientName": "Service Client"
                    }
                    """;

            JsonNode confidentialClientResp = httpJson(http, "POST", base + "/clients", confidentialClientReq);
            String confClientId = confidentialClientResp.get("clientId").asText();
            String confClientSecret = confidentialClientResp.get("clientSecret").asText(); // only returned on creation

            System.out.println();
            System.out.println("Saved for later:");
            System.out.println("  confClientId     = " + confClientId);
            System.out.println("  confClientSecret = " + confClientSecret);
            System.out.println();

            // ========== 5) Call client_credentials at /oauth/token ==========
            banner("5) POST /oauth/token (client_credentials grant)");
            System.out.println("Handled by:");
            System.out.println("  OAuthController -> parses form + Basic header -> OAuthTokenRequest");
            System.out.println("  OAuthTokenService -> authenticates client (CONFIDENTIAL => checks secret via PasswordHasherPort.matches)");
            System.out.println("  ClientCredentialsGrantHandler -> issues access token, returns Map");
            System.out.println();
            System.out.println("We will authenticate with HTTP Basic header (RFC 6749).");
            System.out.println();

            String basic = basicAuth(confClientId, confClientSecret);

            String tokenClientCredsForm = form(Map.of(
                    "grant_type", "client_credentials",
                    "scope", "service.read service.write"
            ));

            httpForm(http, base + "/oauth/token", tokenClientCredsForm, basic);

            // ========== 6) Optional: /login convenience endpoint ==========
            banner("6) POST /login (optional convenience endpoint)");
            System.out.println("This depends on YOUR current LoginController implementation.");
            System.out.println();
            System.out.println("Recommended design:");
            System.out.println("  LoginController -> accepts JSON {email,password,scope?}");
            System.out.println("  It internally builds OAuthTokenRequest(grant_type=password, client_id=<PUBLIC login client>, username=email, password=password)");
            System.out.println("  Delegates to OAuthTokenUseCase.token(req)");
            System.out.println("  Returns the SAME OAuth token JSON map as /oauth/token.");
            System.out.println();
            System.out.println("If your LoginController is still the old BasicLoginUseCase version, this call may fail until you refactor it.");
            System.out.println();

            String loginJson = """
                    {
                      "email": "mahd@example.com",
                      "password": "pass1234",
                      "scope": "read write"
                    }
                    """;

            // If you refactored /login as recommended, it MUST know which client_id to use internally.
            // You can hardcode the public client id in LoginController, or (better) inject it.
            // This call just shows the request/response.
            httpJson(http, "POST", base + "/login", loginJson);

        } finally {
            banner("SHUTDOWN");
            server.stop(0);
            System.out.println("Server stopped.");
        }
    }

    // ---------------- HTTP helpers ----------------

    private static JsonNode httpJson(HttpClient http, String method, String url, String jsonBody) throws Exception {
        System.out.println("REQUEST");
        System.out.println(method + " " + url);
        System.out.println("Content-Type: application/json");
        System.out.println("Body:");
        System.out.println(jsonBody.trim());
        System.out.println();

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());

        System.out.println("RESPONSE");
        System.out.println("HTTP " + resp.statusCode());
        resp.headers().map().forEach((k, v) -> System.out.println(k + ": " + String.join(", ", v)));
        System.out.println("Body:");
        System.out.println(prettyJsonOrRaw(resp.body()));
        System.out.println();

        return tryParseJson(resp.body());
    }

    private static JsonNode httpForm(HttpClient http, String url, String formBody, String basicAuthHeader) throws Exception {
        System.out.println("REQUEST");
        System.out.println("POST " + url);
        System.out.println("Content-Type: application/x-www-form-urlencoded");
        if (basicAuthHeader != null) {
            System.out.println("Authorization: " + basicAuthHeader);
        }
        System.out.println("Body:");
        System.out.println(formBody);
        System.out.println();

        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody));

        if (basicAuthHeader != null) b.header("Authorization", basicAuthHeader);

        HttpResponse<String> resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());

        System.out.println("RESPONSE");
        System.out.println("HTTP " + resp.statusCode());
        resp.headers().map().forEach((k, v) -> System.out.println(k + ": " + String.join(", ", v)));
        System.out.println("Body:");
        System.out.println(prettyJsonOrRaw(resp.body()));
        System.out.println();

        return tryParseJson(resp.body());
    }

    // ---------------- formatting helpers ----------------

    private static void banner(String title) {
        System.out.println("============================================================");
        System.out.println(title);
        System.out.println("============================================================");
    }

    private static String prettyJsonOrRaw(String body) {
        try {
            JsonNode n = om.readTree(body);
            return om.writerWithDefaultPrettyPrinter().writeValueAsString(n);
        } catch (Exception ignore) {
            return body;
        }
    }

    private static JsonNode tryParseJson(String body) {
        try {
            return om.readTree(body);
        } catch (Exception e) {
            return om.nullNode();
        }
    }

    private static String form(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (!first) sb.append("&");
            first = false;
            sb.append(enc(e.getKey())).append("=").append(enc(e.getValue()));
        }
        return sb.toString();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String basicAuth(String clientId, String clientSecret) {
        String raw = clientId + ":" + clientSecret;
        String b64 = Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
        return "Basic " + b64;
    }
}