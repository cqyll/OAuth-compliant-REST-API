package io.github.cqyll.todoapi;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import io.github.cqyll.todoapi.domain.OAuthClient;

import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;


/*
 * OAuthClient is the servers representation of a registered client application. Other parts of the system rely on it during token processing:
 * - OAuthTokenService.authenticateClient() uses it to decide whether the client exists, is enabled, to determine client type, etc.
 * - OAuthTokenService.token() uses it to decide if a client is authorized for a given grant type
 * - OAuthTokenService.resolveEffectiveScopes() uses it as an authoritative source of what scopes the client may get
 * - Grant handlers may rely on instances this class to enforce policy 
 */

final class OAuthClientTestF {
	
	@Nested
	final class FactoryInvariants {

	    @Test
	    void createPublic_setsPublicType_andNullSecretHash() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertEquals("pub1", c.getClientId());
	        assertEquals(OAuthClient.ClientType.PUBLIC, c.getClientType());
	        assertNull(c.getClientSecretHash());
	        assertEquals(EnumSet.of(OAuthClient.GrantType.PASSWORD), c.getAllowedGrantTypes());
	        assertTrue(c.isEnabled());
	        assertEquals(1L, c.getCreatedAtEpochMillis());
	    }

	    @Test
	    void createConfidential_setsConfidentialType_andStoresSecretHash() {
	        OAuthClient c = OAuthClient.createConfidential(
	                "conf1",
	                "HASH(secret)",
	                EnumSet.of(OAuthClient.GrantType.CLIENT_CREDENTIALS),
	                List.of(),
	                List.of("read"),
	                OAuthClient.Metadata.empty(),
	                false,
	                2L
	        );

	        assertEquals("conf1", c.getClientId());
	        assertEquals(OAuthClient.ClientType.CONFIDENTIAL, c.getClientType());
	        assertEquals("HASH(secret)", c.getClientSecretHash());
	        assertEquals(EnumSet.of(OAuthClient.GrantType.CLIENT_CREDENTIALS), c.getAllowedGrantTypes());
	        assertFalse(c.isEnabled());
	        assertEquals(2L, c.getCreatedAtEpochMillis());
	    }

	    @Test
	    void createPublic_rejectsBlankClientId() {
	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.createPublic(
	                        "   ",
	                        EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                        List.of(),
	                        List.of("read"),
	                        OAuthClient.Metadata.empty(),
	                        true,
	                        1L
	                )
	        );

	        assertEquals("clientId is required", e.getMessage());
	    }

	    @Test
	    void createConfidential_rejectsBlankSecretHash() {
	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.createConfidential(
	                        "conf1",
	                        "   ",
	                        EnumSet.of(OAuthClient.GrantType.CLIENT_CREDENTIALS),
	                        List.of(),
	                        List.of("read"),
	                        OAuthClient.Metadata.empty(),
	                        true,
	                        1L
	                )
	        );

	        assertEquals("clientSecretHash is required for confidential clients", e.getMessage());
	    }

	    @Test
	    void factories_rejectEmptyAllowedGrantTypes() {
	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.createPublic(
	                        "pub1",
	                        Set.of(),
	                        List.of(),
	                        List.of("read"),
	                        OAuthClient.Metadata.empty(),
	                        true,
	                        1L
	                )
	        );

	        assertEquals("allowedGrantTypes must be non-empty", e.getMessage());
	    }

	    @Test
	    void factories_rejectNullGrantTypeElement() {
	        Set<OAuthClient.GrantType> grants = new LinkedHashSet<>();
	        grants.add(OAuthClient.GrantType.PASSWORD);
	        grants.add(null);

	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.createPublic(
	                        "pub1",
	                        grants,
	                        List.of(),
	                        List.of("read"),
	                        OAuthClient.Metadata.empty(),
	                        true,
	                        1L
	                )
	        );

	        assertEquals("allowedGrantTypes must not contain null", e.getMessage());
	    }

	    @Test
	    void factories_rejectNonPositiveCreatedAt() {
	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.createPublic(
	                        "pub1",
	                        EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                        List.of(),
	                        List.of("read"),
	                        OAuthClient.Metadata.empty(),
	                        true,
	                        0L
	                )
	        );

	        assertEquals("createdAtEpochMillis must be > 0", e.getMessage());
	    }
	}
	
	@Nested
	final class RedirectUriNormalizationAndValidation {

	    @Test
	    void createPublic_nullRedirectUris_becomesEmptyList() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                null,
	                List.of("read"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertNotNull(c.getRedirectUris());
	        assertTrue(c.getRedirectUris().isEmpty());
	    }

	    @Test
	    void redirectUris_areTrimmedAndDeduped() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(
	                        " https://a.example/cb  ",
	                        "https://a.example/cb",
	                        "https://b.example/cb"
	                ),
	                List.of("read"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertEquals(
	                List.of("https://a.example/cb", "https://b.example/cb"),
	                c.getRedirectUris()
	        );
	    }

	    @Test
	    void redirectUris_rejectBlankElement() {
	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.createPublic(
	                        "pub1",
	                        EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                        List.of("   "),
	                        List.of("read"),
	                        OAuthClient.Metadata.empty(),
	                        true,
	                        1L
	                )
	        );

	        assertEquals("redirect_uri must not be blank", e.getMessage());
	    }

	    @Test
	    void redirectUris_rejectInvalidUri() {
	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.createPublic(
	                        "pub1",
	                        EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                        List.of("ht!tp://bad"),
	                        List.of("read"),
	                        OAuthClient.Metadata.empty(),
	                        true,
	                        1L
	                )
	        );

	        assertTrue(e.getMessage().startsWith("redirect_uri must be a valid URI: "));
	    }

	    @Test
	    void redirectUris_rejectFragment() {
	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.createPublic(
	                        "pub1",
	                        EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                        List.of("https://a.example/cb#frag"),
	                        List.of("read"),
	                        OAuthClient.Metadata.empty(),
	                        true,
	                        1L
	                )
	        );

	        assertTrue(e.getMessage().startsWith("redirect_uri must not include fragment: "));
	    }
	}
	
	@Nested
	final class ScopeNormalizationAndStorage {

	    @Test
	    void normalizeScopeTokens_nullOrBlank_returnsEmptySet() {
	        assertEquals(Set.of(), OAuthClient.normalizeScopeTokens(null));
	        assertEquals(Set.of(), OAuthClient.normalizeScopeTokens("   "));
	    }

	    @Test
	    void normalizeScopeTokens_lowercasesAndDedupes() {
	        Set<String> out = OAuthClient.normalizeScopeTokens("  READ write read  ");

	        assertEquals(Set.of("read", "write"), out);
	        assertEquals(2, out.size());
	        assertThrows(UnsupportedOperationException.class, () -> out.add("new"));
	    }

	    @Test
	    void normalizeScopeTokens_rejectsInvalidToken() {
	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.normalizeScopeTokens("read bad!!")
	        );

	        assertEquals("invalid scope token: bad!!", e.getMessage());
	    }

	    @Test
	    void createPublic_nullAllowedScopes_becomesEmptySet() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                null,
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertNotNull(c.getAllowedScopes());
	        assertTrue(c.getAllowedScopes().isEmpty());
	    }

	    @Test
	    void factory_normalizesAllowedScopes() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of(" READ ", "write", "read"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertEquals(Set.of("read", "write"), c.getAllowedScopes());
	        assertEquals(2, c.getAllowedScopes().size());
	    }
	}
	
	@Nested
	final class MetadataNormalization {

	    @Test
	    void factory_acceptsNullMetadata_andStoresEmptyMetadataState() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read"),
	                null,
	                true,
	                1L
	        );

	        assertNull(c.getMetadata().getClientName());
	        assertNull(c.getMetadata().getClientUri());
	        assertNull(c.getMetadata().getLogoUri());
	        assertNull(c.getMetadata().getPolicyUri());
	    }

	    @Test
	    void metadata_textFields_trimAndBlankToNull() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read"),
	                OAuthClient.Metadata.of(
	                        "  My App  ",
	                        " https://app.example ",
	                        "   ",
	                        " https://policy.example ",
	                        " Example description "
	                ),
	                true,
	                1L
	        );

	        assertEquals("My App", c.getMetadata().getClientName());
	        assertEquals("https://app.example", c.getMetadata().getClientUri());
	        assertNull(c.getMetadata().getLogoUri());
	        assertEquals("https://policy.example", c.getMetadata().getPolicyUri());
	        assertEquals("Example description", c.getMetadata().getDescription());
	    }

	    @Test
	    void metadata_rejectsTooLongText() {
	        String tooLong = "a".repeat(256);

	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.createPublic(
	                        "pub1",
	                        EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                        List.of(),
	                        List.of("read"),
	                        OAuthClient.Metadata.of(
	                                tooLong,
	                                null,
	                                null,
	                                null,
	                                null
	                        ),
	                        true,
	                        1L
	                )
	        );

	        assertEquals("clientName too long", e.getMessage());
	    }

	    @Test
	    void metadata_rejectsInvalidUriFields() {
	        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
	                OAuthClient.createPublic(
	                        "pub1",
	                        EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                        List.of(),
	                        List.of("read"),
	                        OAuthClient.Metadata.of(
	                                "My App",
	                                "ht!tp://bad",
	                                null,
	                                null,
	                                null
	                        ),
	                        true,
	                        1L
	                )
	        );

	        assertTrue(e.getMessage().startsWith("clientUri must be a valid URI"));
	    }
	}
	
	@Nested
	final class RepresentationSafety {

	    @Test
	    void allowedGrantTypes_getterReturnsUnmodifiableSet() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertThrows(UnsupportedOperationException.class, () ->
	                c.getAllowedGrantTypes().add(OAuthClient.GrantType.CLIENT_CREDENTIALS)
	        );
	    }

	    @Test
	    void redirectUris_getterReturnsUnmodifiableList() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of("https://a.example/cb"),
	                List.of("read"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertThrows(UnsupportedOperationException.class, () ->
	                c.getRedirectUris().add("https://b.example/cb")
	        );
	    }

	    @Test
	    void allowedScopes_getterReturnsUnmodifiableSet() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertThrows(UnsupportedOperationException.class, () ->
	                c.getAllowedScopes().add("write")
	        );
	    }
	}
	
	@Nested
	final class ScopeAuthorizationBehavior {

	    @Test
	    void allowsScopes_nullRequestedScopes_returnsTrue() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read", "write"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertTrue(c.allowsScopes(null));
	    }

	    @Test
	    void allowsScopes_emptyRequestedScopes_returnsTrue() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read", "write"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertTrue(c.allowsScopes(Set.of()));
	    }

	    @Test
	    void allowsScopes_subset_returnsTrue() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read", "write"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertTrue(c.allowsScopes(Set.of("read")));
	        assertTrue(c.allowsScopes(Set.of("read", "write")));
	    }

	    @Test
	    void allowsScopes_nonSubset_returnsFalse() {
	        OAuthClient c = OAuthClient.createPublic(
	                "pub1",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read", "write"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        assertFalse(c.allowsScopes(Set.of("admin")));
	        assertFalse(c.allowsScopes(Set.of("read", "admin")));
	    }
	}
	
	@Nested
	final class GrantTypeContract {

	    @Test
	    void grantType_value_returnsProtocolValue() {
	        assertEquals("password", OAuthClient.GrantType.PASSWORD.value());
	        assertEquals("client_credentials", OAuthClient.GrantType.CLIENT_CREDENTIALS.value());
	        assertEquals("authorization_code", OAuthClient.GrantType.AUTHORIZATION_CODE.value());
	        assertEquals("refresh_token", OAuthClient.GrantType.REFRESH_TOKEN.value());
	    }

	    @Test
	    void grantType_fromString_matchesKnownValue() {
	        assertSame(
	                OAuthClient.GrantType.PASSWORD,
	                OAuthClient.GrantType.fromString("password")
	        );
	        assertSame(
	                OAuthClient.GrantType.CLIENT_CREDENTIALS,
	                OAuthClient.GrantType.fromString("client_credentials")
	        );
	        assertSame(
	                OAuthClient.GrantType.AUTHORIZATION_CODE,
	                OAuthClient.GrantType.fromString("authorization_code")
	        );
	        assertSame(
	                OAuthClient.GrantType.REFRESH_TOKEN,
	                OAuthClient.GrantType.fromString("refresh_token")
	        );
	    }

	    @Test
	    void grantType_fromString_trimsInput() {
	        assertSame(
	                OAuthClient.GrantType.PASSWORD,
	                OAuthClient.GrantType.fromString("  password  ")
	        );
	    }

	    @Test
	    void grantType_fromString_isCaseSensitive() {
	        assertNull(OAuthClient.GrantType.fromString("PASSWORD"));
	        assertNull(OAuthClient.GrantType.fromString("Password"));
	    }

	    @Test
	    void grantType_fromString_nullOrUnknown_returnsNull() {
	        assertNull(OAuthClient.GrantType.fromString(null));
	        assertNull(OAuthClient.GrantType.fromString("banana"));
	        assertNull(OAuthClient.GrantType.fromString("implicit"));
	    }
	}
	
	
	@Nested
	final class ObjectContract {

	    @Test
	    void equals_sameClientId_returnsTrue_evenIfOtherFieldsDiffer() {
	        OAuthClient a = OAuthClient.createPublic(
	                "same",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        OAuthClient b = OAuthClient.createConfidential(
	                "same",
	                "HASH(secret)",
	                EnumSet.of(OAuthClient.GrantType.CLIENT_CREDENTIALS),
	                List.of("https://a.example/cb"),
	                List.of("write"),
	                OAuthClient.Metadata.of(
	                        "My App",
	                        "https://app.example",
	                        null,
	                        null,
	                        null
	                ),
	                false,
	                2L
	        );

	        assertEquals(a, b);
	    }

	    @Test
	    void hashCode_sameClientId_matches() {
	        OAuthClient a = OAuthClient.createPublic(
	                "same",
	                EnumSet.of(OAuthClient.GrantType.PASSWORD),
	                List.of(),
	                List.of("read"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        OAuthClient b = OAuthClient.createConfidential(
	                "same",
	                "HASH(secret)",
	                EnumSet.of(OAuthClient.GrantType.CLIENT_CREDENTIALS),
	                List.of("https://a.example/cb"),
	                List.of("write"),
	                OAuthClient.Metadata.empty(),
	                false,
	                2L
	        );

	        assertEquals(a.hashCode(), b.hashCode());
	    }

	    @Test
	    void toString_doesNotContainClientSecretHash() {
	        OAuthClient c = OAuthClient.createConfidential(
	                "conf1",
	                "HASH(secret)",
	                EnumSet.of(OAuthClient.GrantType.CLIENT_CREDENTIALS),
	                List.of(),
	                List.of("read"),
	                OAuthClient.Metadata.empty(),
	                true,
	                1L
	        );

	        String s = c.toString();

	        assertTrue(s.contains("clientId='conf1'"));
	        assertFalse(s.contains("HASH(secret)"));
	        assertFalse(s.contains("clientSecretHash"));
	    }
	}
	
}
