// OAuthClient.java
package io.github.cqyll.todoapi.domain;

import java.net.URI;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

public class OAuthClient {

    public enum ClientType {
        CONFIDENTIAL,
        PUBLIC
    }

    public enum GrantType {
        CLIENT_CREDENTIALS("client_credentials"),
        AUTHORIZATION_CODE("authorization_code"),
        REFRESH_TOKEN("refresh_token"),
        PASSWORD("password"); // discouraged

        private final String value;

        GrantType(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }

        /*
         * returns existing enum instance
         * Avoid Enum.valueOf(): couples to Java enum names, also invalid protocol input is expected here, not exceptional
         */
        public static GrantType fromString(String raw) {
            if (raw == null) return null;
            String s = raw.trim();
            for (GrantType gt : values()) {
                if (gt.value.equals(s)) return gt;
            }
            return null;
        }
    }

    private final String clientId;
    private final String clientSecretHash; // null for public clients
    private final ClientType clientType;

    private final Set<GrantType> allowedGrantTypes; // non-empty
    private final List<String> redirectUris;

    private final Set<String> allowedScopes; // may be empty

    // optional client metadata (all nullable)
    private final String clientName;
    private final String clientUri;
    private final String logoUri;
    private final String policyUri;
    private final String description;

    private final boolean enabled;
    private final long createdAtEpochMillis;

    private OAuthClient(Builder b) {
        this.clientId = b.clientId;
        this.clientSecretHash = b.clientSecretHash;
        this.clientType = b.clientType;
        this.allowedGrantTypes = Collections.unmodifiableSet(b.allowedGrantTypes);
        this.redirectUris = Collections.unmodifiableList(b.redirectUris);
        this.allowedScopes = Collections.unmodifiableSet(b.allowedScopes);

        this.clientName = b.clientName;
        this.clientUri = b.clientUri;
        this.logoUri = b.logoUri;
        this.policyUri = b.policyUri;
        this.description = b.description;

        this.enabled = b.enabled;
        this.createdAtEpochMillis = b.createdAtEpochMillis;
    }

    // getters
    public String getClientId() { return clientId; }
    public String getClientSecretHash() { return clientSecretHash; }
    public ClientType getClientType() { return clientType; }
    public Set<GrantType> getAllowedGrantTypes() { return allowedGrantTypes; }
    public List<String> getRedirectUris() { return redirectUris; }
    public Set<String> getAllowedScopes() { return allowedScopes; }
    public String getClientName() { return clientName; }
    public String getClientUri() { return clientUri; }
    public String getLogoUri() { return logoUri; }
    public String getPolicyUri() { return policyUri; }
    public String getDescription() { return description; }
    public boolean isEnabled() { return enabled; }
    public long getCreatedAtEpochMillis() { return createdAtEpochMillis; }

   
    public boolean allowsScopes(Set<String> requestedScopesNormalized) {
        if (requestedScopesNormalized == null || requestedScopesNormalized.isEmpty()) return true;
        return allowedScopes.containsAll(requestedScopesNormalized);
    }

    // factories

    public static OAuthClient createConfidential(
            String clientId,
            String clientSecretHash,
            Set<GrantType> allowedGrantTypes,
            List<String> redirectUris,
            List<String> allowedScopes,
            Metadata metadata,
            boolean enabled,
            long createdAtEpochMillis) {

        Builder b = new Builder();
        b.clientId = requireNonBlank(clientId, "clientId is required");
        b.clientType = ClientType.CONFIDENTIAL;
        b.clientSecretHash = requireNonBlank(clientSecretHash, "clientSecretHash is required for confidential clients");
        b.allowedGrantTypes = normalizeGrants(allowedGrantTypes);
        b.redirectUris = normalizeRedirectUris(redirectUris);
        b.allowedScopes = normalizeScopes(allowedScopes);

        applyMetadata(b, metadata);

        b.enabled = enabled;
        b.createdAtEpochMillis = requirePositive(createdAtEpochMillis, "createdAtEpochMillis must be > 0");

        if (b.clientSecretHash == null) {
            throw new IllegalArgumentException("Confidential client must have a clientSecretHash");
        }

        return new OAuthClient(b);
    }

    public static OAuthClient createPublic(
            String clientId,
            Set<GrantType> allowedGrantTypes,
            List<String> redirectUris,
            List<String> allowedScopes,
            Metadata metadata,
            boolean enabled,
            long createdAtEpochMillis) {

        Builder b = new Builder();
        b.clientId = requireNonBlank(clientId, "clientId is required");
        b.clientType = ClientType.PUBLIC;
        b.clientSecretHash = null;
        b.allowedGrantTypes = normalizeGrants(allowedGrantTypes);
        b.redirectUris = normalizeRedirectUris(redirectUris);
        b.allowedScopes = normalizeScopes(allowedScopes);

        applyMetadata(b, metadata);

        b.enabled = enabled;
        b.createdAtEpochMillis = requirePositive(createdAtEpochMillis, "createdAtEpochMillis must be > 0");

        if (b.clientSecretHash != null) {
            throw new IllegalArgumentException("Public client must not have a clientSecretHash");
        }

        return new OAuthClient(b);
    }

    // metadata

    public static final class Metadata {
        private final String clientName;
        private final String clientUri;
        private final String logoUri;
        private final String policyUri;
        private final String description;

        private Metadata(String clientName, String clientUri, String logoUri, String policyUri, String description) {
            this.clientName = clientName;
            this.clientUri = clientUri;
            this.logoUri = logoUri;
            this.policyUri = policyUri;
            this.description = description;
        }

        public static Metadata of(String clientName, String clientUri, String logoUri, String policyUri, String description) {
            return new Metadata(clientName, clientUri, logoUri, policyUri, description);
        }

        public static Metadata empty() {
            return new Metadata(null, null, null, null, null);
        }
    }

    // internals

    private static final class Builder {
        String clientId;
        String clientSecretHash;
        ClientType clientType;

        Set<GrantType> allowedGrantTypes;
        List<String> redirectUris;

        Set<String> allowedScopes;

        String clientName;
        String clientUri;
        String logoUri;
        String policyUri;
        String description;

        boolean enabled;
        long createdAtEpochMillis;
    }

    private static void applyMetadata(Builder b, Metadata m) {
        Metadata meta = (m == null) ? Metadata.empty() : m;

        b.clientName = normalizeOptionalText(meta.clientName, 200, "clientName");
        b.description = normalizeOptionalText(meta.description, 2000, "description");
        b.clientUri = normalizeOptionalUri(meta.clientUri, "clientUri");
        b.logoUri = normalizeOptionalUri(meta.logoUri, "logoUri");
        b.policyUri = normalizeOptionalUri(meta.policyUri, "policyUri");
    }

    private static Set<GrantType> normalizeGrants(Set<GrantType> grants) {
        if (grants == null || grants.isEmpty()) {
            throw new IllegalArgumentException("allowedGrantTypes must be non-empty");
        }
        EnumSet<GrantType> set = EnumSet.noneOf(GrantType.class);
        for (GrantType g : grants) {
            if (g == null) throw new IllegalArgumentException("allowedGrantTypes must not contain null");
            set.add(g);
        }
        if (set.isEmpty()) throw new IllegalArgumentException("allowedGrantTypes must be non-empty");
        return set;
    }

    private static List<String> normalizeRedirectUris(List<String> redirectUris) {
        if (redirectUris == null) return List.of();

        Set<String> uniq = new LinkedHashSet<>();
        for (String raw : redirectUris) {
            String uriStr = requireNonBlank(raw, "redirect_uri must not be blank").trim();
            validateRedirectUriInvariant(uriStr);
            uniq.add(uriStr);
        }
        return List.copyOf(uniq);
    }

    /**
     * Scope normalization helper:
     * - trims
     * - lowercases
     * - removes duplicates (order-preserving)
     * - validates token characters
     */
    public static Set<String> normalizeScopeTokens(Iterable<String> rawScopes) {
        return Collections.unmodifiableSet(normalizeScopes(rawScopes));
    }
    
    public static Set<String> normalizeScopeTokens(String scopeRaw) {
    	if (scopeRaw == null || scopeRaw.isBlank()) return Set.of();
    	return normalizeScopeTokens(List.of(scopeRaw.trim().split("\\s+")));
    }
    
    // internal normalize (mutable) used by builder
    private static Set<String> normalizeScopes(Iterable<String> rawScopes) {
        if (rawScopes == null) return Set.of();

        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String raw : rawScopes) {
            String tok = requireNonBlank(raw, "scope token must not be blank")
            		.trim().
            		toLowerCase(Locale.ROOT);
            validateScopeToken(tok);
            out.add(tok);
        }
        return out;
    }

    // RFC6749 scope-token
    private static final Pattern SCOPE_TOKEN = Pattern.compile("^[a-z0-9._:-]+$");

    private static void validateScopeToken(String tok) {
        if (!SCOPE_TOKEN.matcher(tok).matches()) {
            throw new IllegalArgumentException("invalid scope token: " + tok);
        }
    }

    /**
     * Invariant-level validation:
     * - must parse as URI
     * - MUST NOT include fragment (#...)
     */
    private static void validateRedirectUriInvariant(String uriStr) {
        URI uri;
        try {
            uri = URI.create(uriStr);
        } catch (Exception e) {
            throw new IllegalArgumentException("redirect_uri must be a valid URI: " + uriStr);
        }
        if (uri.getFragment() != null) {
            throw new IllegalArgumentException("redirect_uri must not include fragment: " + uriStr);
        }
    }

    private static String requireNonBlank(String s, String msg) {
        if (s == null || s.isBlank()) throw new IllegalArgumentException(msg);
        return s;
    }

    private static long requirePositive(long v, String msg) {
        if (v <= 0) throw new IllegalArgumentException(msg);
        return v;
    }

    private static String normalizeOptionalText(String s, int maxLen, String field) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;
        if (t.length() > maxLen) throw new IllegalArgumentException(field + " too long");
        return t;
    }

    private static String normalizeOptionalUri(String s, String field) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;
        try {
            URI.create(t);
        } catch (Exception e) {
            throw new IllegalArgumentException(field + " must be a valid URI");
        }
        return t;
    }

    @Override
    public String toString() {
        return "OAuthClient{" +
                "clientId='" + clientId + '\'' +
                ", clientType=" + clientType +
                ", allowedGrantTypes=" + allowedGrantTypes +
                ", redirectUris=" + redirectUris +
                ", allowedScopes=" + allowedScopes +
                ", enabled=" + enabled +
                ", createdAtEpochMillis=" + createdAtEpochMillis +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OAuthClient that)) return false;
        return Objects.equals(clientId, that.clientId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId);
    }
}