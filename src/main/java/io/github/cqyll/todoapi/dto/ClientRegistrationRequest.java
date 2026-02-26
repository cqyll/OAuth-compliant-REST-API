package io.github.cqyll.todoapi.dto;

import java.util.List;

public class ClientRegistrationRequest {
    private String clientType; // "confidential" | "public"
    private List<String> grantTypes;
    private List<String> redirectUris;
    private List<String> scopes;

    private String clientName;
    private String clientUri;
    private String logoUri;
    private String policyUri;
    private String description;

    public ClientRegistrationRequest() {}

    public String getClientType() { return clientType; }
    public void setClientType(String clientType) { this.clientType = clientType; }

    public List<String> getGrantTypes() { return grantTypes; }
    public void setGrantTypes(List<String> grantTypes) { this.grantTypes = grantTypes; }

    public List<String> getRedirectUris() { return redirectUris; }
    public void setRedirectUris(List<String> redirectUris) { this.redirectUris = redirectUris; }
    
    public List<String> getScopes() { return scopes; }
    public void setScopes(List<String> scopes) { this.scopes = scopes; }

    public String getClientName() { return clientName; }
    public void setClientName(String clientName) { this.clientName = clientName; }

    public String getClientUri() { return clientUri; }
    public void setClientUri(String clientUri) { this.clientUri = clientUri; }

    public String getLogoUri() { return logoUri; }
    public void setLogoUri(String logoUri) { this.logoUri = logoUri; }

    public String getPolicyUri() { return policyUri; }
    public void setPolicyUri(String policyUri) { this.policyUri = policyUri; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}