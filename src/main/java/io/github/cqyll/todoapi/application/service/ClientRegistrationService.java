package io.github.cqyll.todoapi.application.service;

import io.github.cqyll.todoapi.application.port.inbound.ClientRegistrationUseCase;
import io.github.cqyll.todoapi.application.port.outbound.OAuthClientRepositoryPort;
import io.github.cqyll.todoapi.application.port.outbound.PasswordHasherPort;
import io.github.cqyll.todoapi.domain.OAuthClient;
import io.github.cqyll.todoapi.dto.ClientRegistrationRequest;
import io.github.cqyll.todoapi.dto.ClientRegistrationResponse;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.Base64;

public class ClientRegistrationService implements ClientRegistrationUseCase {
    private final OAuthClientRepositoryPort clientRepo;
    private final PasswordHasherPort hasher;
    private final SecureRandom random = new SecureRandom();

    public ClientRegistrationService(OAuthClientRepositoryPort clientRepo, PasswordHasherPort hasher) {
        this.clientRepo = clientRepo;
        this.hasher = hasher;
    }

    @Override
    public ClientRegistrationResponse register(ClientRegistrationRequest req) {
        if (req == null) throw new IllegalArgumentException("request is required");

        OAuthClient.ClientType type = parseClientType(req.getClientType());
        Set<OAuthClient.GrantType> grants = parseGrantTypes(req.getGrantTypes());
        List<String> redirectUris = (req.getRedirectUris() == null) ? List.of() : req.getRedirectUris();
        List<String> scopes = (req.getScopes() == null) ? List.of() : req.getScopes();

        String clientId = generateId("client");
        String rawSecret = null;

        OAuthClient.Metadata meta = OAuthClient.Metadata.of(
                req.getClientName(),
                req.getClientUri(),
                req.getLogoUri(),
                req.getPolicyUri(),
                req.getDescription()
        );

        long now = Instant.now().toEpochMilli();

        OAuthClient client;
        if (type == OAuthClient.ClientType.CONFIDENTIAL) {
            rawSecret = generateSecret();
            String secretHash = hasher.hash(rawSecret);
            client = OAuthClient.createConfidential(
                    clientId,
                    secretHash,
                    grants,
                    redirectUris,
                    scopes,
                    meta,
                    true,
                    now
            );
        } else {
            client = OAuthClient.createPublic(
                    clientId,
                    grants,
                    redirectUris,
                    scopes,
                    meta,
                    true,
                    now
            );
        }

        clientRepo.save(client);

        return new ClientRegistrationResponse(
                client.getClientId(),
                rawSecret,
                client.getClientType().name().toLowerCase(),
                grants.stream().map(OAuthClient.GrantType::value).toList(),
                client.getRedirectUris()
        );
    }

    private OAuthClient.ClientType parseClientType(String raw) {
        if (raw == null) throw new IllegalArgumentException("clientType is required");
        String v = raw.trim().toLowerCase();
        return switch (v) {
            case "confidential" -> OAuthClient.ClientType.CONFIDENTIAL;
            case "public" -> OAuthClient.ClientType.PUBLIC;
            default -> throw new IllegalArgumentException("clientType must be 'confidential' or 'public'");
        };
    }

    private Set<OAuthClient.GrantType> parseGrantTypes(List<String> raw) {
        if (raw == null || raw.isEmpty()) {
            throw new IllegalArgumentException("grantTypes must be non-empty");
        }
        EnumSet<OAuthClient.GrantType> set = EnumSet.noneOf(OAuthClient.GrantType.class);
        for (String s : raw) {
            OAuthClient.GrantType gt = OAuthClient.GrantType.fromString(s);
            if (gt == null) throw new IllegalArgumentException("unknown grant type: " + s);
            set.add(gt);
        }
        if (set.isEmpty()) throw new IllegalArgumentException("grantTypes must be non-empty");
        return set;
    }

    private String generateId(String prefix) {
        byte[] buf = new byte[18];
        random.nextBytes(buf);
        return prefix + "_" + Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private String generateSecret() {
        byte[] buf = new byte[32];
        random.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}