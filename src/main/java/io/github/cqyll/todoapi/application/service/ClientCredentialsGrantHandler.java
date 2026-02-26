package io.github.cqyll.todoapi.application.service;

import io.github.cqyll.todoapi.adapter.inbound.web.OAuthError;
import io.github.cqyll.todoapi.application.port.outbound.TokenProviderPort;
import io.github.cqyll.todoapi.application.service.OAuthTokenService.GrantContext;
import io.github.cqyll.todoapi.domain.OAuthClient;
import io.github.cqyll.todoapi.dto.OAuthTokenRequest;

import java.util.LinkedHashMap;
import java.util.Map;

public final class ClientCredentialsGrantHandler implements TokenGrantHandler {

    private final TokenProviderPort tokens;

    public ClientCredentialsGrantHandler(TokenProviderPort tokens) {
        this.tokens = tokens;
    }

    @Override
    public OAuthClient.GrantType supports() {
        return OAuthClient.GrantType.CLIENT_CREDENTIALS;
    }

    @Override
    public Map<String, Object> handle(GrantContext ctx, OAuthTokenRequest req) {
        OAuthClient client = ctx.client();

        // no user creds
        rejectIfPresent(req.getUsername(), "username/password not allowed for client_credentials grant");
        rejectIfPresent(req.getPassword(), "username/password not allowed for client_credentials grant");

        // reject other grant params
        rejectIfPresent(req.getCode(), "code is not allowed for client_credentials grant");
        rejectIfPresent(req.getRedirectUri(), "redirect_uri is not allowed for client_credentials grant");
        rejectIfPresent(req.getRefreshToken(), "refresh_token is not allowed for client_credentials grant");

        if (client.getClientType() != OAuthClient.ClientType.CONFIDENTIAL) {
            throw OAuthError.unauthorizedClient("public clients cannot use client_credentials grant");
        }

        String access = tokens.createToken(client.getClientId());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("access_token", access);
        out.put("token_type", "Bearer");
        out.put("expires_in", 3600);

     // RFC 6749 s.3.3: include "scope" in the response to indicate the granted scope (especially if defaulted or adjusted).
        if (!ctx.effectiveScopes().isEmpty()) {
            out.put("scope", String.join(" ", ctx.effectiveScopes()));
        }

        return out;
    }

    private static void rejectIfPresent(String v, String msg) {
        if (v != null && !v.isBlank()) throw OAuthError.invalidRequest(msg);
    }
}