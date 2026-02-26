package io.github.cqyll.todoapi.adapter.inbound.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.github.cqyll.todoapi.application.port.inbound.ClientRegistrationUseCase;
import io.github.cqyll.todoapi.dto.ClientRegistrationRequest;
import io.github.cqyll.todoapi.dto.ClientRegistrationResponse;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class ClientRegistrationController implements HttpHandler {
    private static final ObjectMapper mapper = new ObjectMapper();
    private final ClientRegistrationUseCase useCase;

    public ClientRegistrationController(ClientRegistrationUseCase useCase) {
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
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            ClientRegistrationRequest req = mapper.readValue(body, ClientRegistrationRequest.class);

            ClientRegistrationResponse resp = useCase.register(req);

            byte[] out = mapper.writeValueAsBytes(resp);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(201, out.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(out);
            }
        } catch (IllegalArgumentException e) {
            byte[] out = mapper.writeValueAsBytes(
                    java.util.Map.of("error", "invalid_request", "error_description", e.getMessage())
            );
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(400, out.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(out);
            }
        }
    }
}