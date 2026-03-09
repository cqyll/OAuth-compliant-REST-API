package io.github.cqyll.todoapi.config;

import com.sun.net.httpserver.HttpServer;
import io.github.cqyll.todoapi.adapter.inbound.web.ClientRegistrationController;
import io.github.cqyll.todoapi.adapter.inbound.web.LoginController;
import io.github.cqyll.todoapi.adapter.inbound.web.OAuthController;
import io.github.cqyll.todoapi.adapter.inbound.web.UserController;
import io.github.cqyll.todoapi.adapter.outbound.persistence.InMemoryOAuthClientAdapter;
import io.github.cqyll.todoapi.adapter.outbound.persistence.InMemoryUserAdapter;
import io.github.cqyll.todoapi.adapter.outbound.security.FakeTokenProviderAdapter;
import io.github.cqyll.todoapi.adapter.outbound.security.SimplePasswordHasherAdapter;
import io.github.cqyll.todoapi.application.port.inbound.ClientRegistrationUseCase;
import io.github.cqyll.todoapi.application.port.inbound.OAuthTokenUseCase;
import io.github.cqyll.todoapi.application.port.outbound.OAuthClientRepositoryPort;
import io.github.cqyll.todoapi.application.port.outbound.PasswordHasherPort;
import io.github.cqyll.todoapi.application.port.outbound.TokenProviderPort;
import io.github.cqyll.todoapi.application.port.outbound.UserRepositoryPort;
import io.github.cqyll.todoapi.application.service.ClientCredentialsGrantHandler;
import io.github.cqyll.todoapi.application.service.ClientRegistrationService;
import io.github.cqyll.todoapi.application.service.OAuthTokenService;
import io.github.cqyll.todoapi.application.service.PasswordGrantHandler;
import io.github.cqyll.todoapi.application.service.TokenGrantHandler;
import io.github.cqyll.todoapi.application.service.UserRegistrationService;
import io.github.cqyll.todoapi.application.port.inbound.UserRegistrationUseCase;

import java.io.IOException;
import java.net.InetSocketAddress;

public final class AppConfig {

    private AppConfig() {}

    public static HttpServer createServer(int port) throws IOException {

        // ===== Outbound adapters =====
        UserRepositoryPort userRepository = new InMemoryUserAdapter();
        OAuthClientRepositoryPort clientRepository = new InMemoryOAuthClientAdapter();
        PasswordHasherPort passwordHasher = new SimplePasswordHasherAdapter();
        TokenProviderPort tokenProvider = new FakeTokenProviderAdapter();

        // ===== Grant handlers =====
        TokenGrantHandler clientCredentialsHandler =
                new ClientCredentialsGrantHandler(tokenProvider);

        PasswordGrantHandler passwordGrantHandler =
                new PasswordGrantHandler(userRepository, passwordHasher, tokenProvider);

        // ===== Application services / use cases =====
        ClientRegistrationUseCase clientRegistrationUseCase =
                new ClientRegistrationService(clientRepository, passwordHasher);

        OAuthTokenUseCase oAuthTokenUseCase =
                new OAuthTokenService(
                        clientRepository,
                        passwordHasher,
                        clientCredentialsHandler,
                        passwordGrantHandler
                );

        UserRegistrationUseCase userRegistrationUseCase =
                new UserRegistrationService(userRepository, passwordHasher, tokenProvider);

        // ===== Controllers =====
        ClientRegistrationController clientRegistrationController =
                new ClientRegistrationController(clientRegistrationUseCase);

        OAuthController oAuthController =
                new OAuthController(oAuthTokenUseCase);

        UserController userController =
                new UserController(userRegistrationUseCase);

        LoginController loginController =
                new LoginController(oAuthTokenUseCase);

        // ===== HTTP server =====
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/clients", clientRegistrationController);
        server.createContext("/oauth/token", oAuthController);
        server.createContext("/users", userController);
        server.createContext("/login", loginController);

        server.setExecutor(null);
        return server;
    }
}