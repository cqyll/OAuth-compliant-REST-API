package io.github.cqyll.todoapi.dto;

import java.util.List;

public class ClientRegistrationResponse {
    private String clientId;
    private String clientSecret; // returned ONLY on creation for confidential clients
    private String clientType;
    private List<String> grantTypes;
    private List<String> redirectUris;

    public ClientRegistrationResponse() {}

    public ClientRegistrationResponse(
            String clientId,
            String clientSecret,
            String clientType,
            List<String> grantTypes,
            List<String> redirectUris
    ) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clientType = clientType;
        this.grantTypes = grantTypes;
        this.redirectUris = redirectUris;
    }

    public String getClientId() { return clientId; }
    public String getClientSecret() { return clientSecret; }
    public String getClientType() { return clientType; }
    public List<String> getGrantTypes() { return grantTypes; }
    public List<String> getRedirectUris() { return redirectUris; }
}