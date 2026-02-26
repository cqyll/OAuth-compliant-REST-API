package io.github.cqyll.todoapi.adapter.inbound.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.github.cqyll.todoapi.application.port.inbound.OAuthTokenUseCase;
import io.github.cqyll.todoapi.dto.OAuthTokenRequest;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class OAuthController implements HttpHandler {

    private static final ObjectMapper mapper = new ObjectMapper();

    private final OAuthTokenUseCase useCase;

    public OAuthController(OAuthTokenUseCase useCase) {
        this.useCase = useCase;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            ex.getResponseHeaders().set("Allow", "POST");
            ex.sendResponseHeaders(405, -1);
            return;
        }

        try {
            String raw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

            Map<String, String> form = parseForm(raw);
            ClientAuth clientAuth = parseClientAuth(ex, form);

            OAuthTokenRequest req = new OAuthTokenRequest(
                    form.get("grant_type"),
                    clientAuth.clientId,
                    clientAuth.clientSecret,
                    form.get("username"),
                    form.get("password"),
                    form.get("code"),
                    form.get("redirect_uri"),
                    form.get("refresh_token"),
                    form.get("scope")
            );

            Map<String, Object> resp = useCase.token(req);

            ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            ex.getResponseHeaders().set("Cache-Control", "no-store");
            ex.getResponseHeaders().set("Pragma", "no-cache");

            writeJson(ex, 200, resp);

        } catch (OAuthError e) {
            writeOAuthError(ex, e);
        } catch (Exception e) {
            writeOAuthError(ex, OAuthError.serverError());
        }
    }

    private void writeOAuthError(HttpExchange ex, OAuthError err) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.getResponseHeaders().set("Pragma", "no-cache");

        if (err.getHttpStatus() == 401) {
            ex.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"oauth\"");
        }

        Map<String, Object> body = new HashMap<>();
        body.put("error", err.getError());

        if (err.getDescription() != null && !err.getDescription().isBlank()) {
            body.put("error_description", err.getDescription());
        }
        if (err.getUri() != null && !err.getUri().isBlank()) {
            body.put("error_uri", err.getUri());
        }

        writeJson(ex, err.getHttpStatus(), body);
    }

    private void writeJson(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = mapper.writeValueAsBytes(body);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }


    private Map<String, String> parseForm(String bodyString) {
        Map<String, String> params = new LinkedHashMap<>();
        if (bodyString == null || bodyString.isBlank()) return params;

        for (String pair : bodyString.split("&")) {
            if (pair.isEmpty()) continue;

            int idx = pair.indexOf('=');
            if (idx < 0) continue;

            String rawKey = pair.substring(0, idx);
            String rawValue = pair.substring(idx + 1);

            if (rawKey.isEmpty()) continue;

            String key = URLDecoder.decode(rawKey, StandardCharsets.UTF_8);
            String value = URLDecoder.decode(rawValue, StandardCharsets.UTF_8);

            if (value.isBlank()) continue;

            if (params.containsKey(key)) {
                throw OAuthError.invalidRequest("Duplicate parameter: " + key);
            }

            params.put(key, value);
        }

        return params;
    }

    private ClientAuth parseClientAuth(HttpExchange ex, Map<String, String> form) {
        String auth = ex.getRequestHeaders().getFirst("Authorization");

        boolean hasBasic = auth != null && auth.startsWith("Basic ");
        boolean hasBodyCreds = form.containsKey("client_id") || form.containsKey("client_secret");

        if (hasBasic && hasBodyCreds) {
            throw OAuthError.invalidRequest("Multiple client authentication methods used");
        }

        if (hasBasic) {
            String b64 = auth.substring("Basic ".length()).trim();
            String decoded = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);

            int idx = decoded.indexOf(':');
            String clientId = (idx >= 0) ? decoded.substring(0, idx) : decoded;
            String clientSecret = (idx >= 0) ? decoded.substring(idx + 1) : "";

            return new ClientAuth(clientId, clientSecret);
        }

        return new ClientAuth(form.get("client_id"), form.get("client_secret"));
    }

    private static final class ClientAuth {
        final String clientId;
        final String clientSecret;

        ClientAuth(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }
    }
}