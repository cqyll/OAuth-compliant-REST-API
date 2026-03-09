package io.github.cqyll.todoapi;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.cqyll.todoapi.dto.OAuthTokenRequest;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("OAuthTokenRequest internals: normalization, trimming, equality, Jackson wiring, safe toString")
final class OAuthTokenRequestTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    @DisplayName("""
    Constructor normalization: grant_type is trimmed + lowercased
    What it tests:
      - grantType normalization is applied at construction time (normalizeGrantType)
      - whitespace is removed and value is lowercased using Locale.ROOT
    Rationale:
      - This DTO is an ingestion boundary. Normalizing here prevents downstream branching on mixed-cased
        input (e.g., "PASSWORD", " password ") and keeps service logic deterministic.
    """)
    void ctor_normalizesGrantType_trimAndLowercase() {
        OAuthTokenRequest req = new OAuthTokenRequest(
                "  PASSWORD  ",
                null, null,
                null, null,
                null, null,
                null,
                null
        );

        assertEquals("password", req.getGrantType());
    }

    @Test
    @DisplayName("""
    Constructor trimming: all string fields are trimToNull
    What it tests:
      - clientId/clientSecret/username/password/code/redirectUri/refreshToken/scope are trimmed
      - empty/blank strings become null (not empty string)
    Rationale:
      - Converting blank strings to null is an internal state-shaping choice that reduces downstream checks
        ("is blank" vs "is null") and prevents accidental acceptance of empty credentials/tokens.
    """)
    void ctor_trimsAllFields_blankBecomesNull() {
        OAuthTokenRequest req = new OAuthTokenRequest(
                "password",
                "  clientA  ",
                "   ",         // -> null
                "  alice  ",
                "   ",         // -> null
                "  abc  ",
                "   ",         // -> null
                "  rt  ",
                "   "          // -> null
        );

        assertEquals("password", req.getGrantType());
        assertEquals("clientA", req.getClientId());
        assertNull(req.getClientSecret());

        assertEquals("alice", req.getUsername());
        assertNull(req.getPassword());

        assertEquals("abc", req.getCode());
        assertNull(req.getRedirectUri());

        assertEquals("rt", req.getRefreshToken());
        assertNull(req.getScope());
    }

    @Test
    @DisplayName("""
    Null-handling: null grant_type remains null (no accidental default)
    What it tests:
      - normalizeGrantType returns null when input is null/blank
    Rationale:
      - The DTO must not invent a grant type. Missing grant_type should remain missing so the service layer
        can map it to a protocol error (e.g., invalid_request) consistently.
    """)
    void ctor_nullGrantType_remainsNull() {
        assertNull(new OAuthTokenRequest(
                null,
                "clientA", null,
                null, null,
                null, null,
                null, null
        ).getGrantType());

        assertNull(new OAuthTokenRequest(
                "   ",
                "clientA", null,
                null, null,
                null, null,
                null, null
        ).getGrantType());
    }

    @Test
    @DisplayName("""
    Jackson wiring: @JsonCreator + @JsonProperty map snake_case fields correctly
    What it tests:
      - JSON properties grant_type/client_id/... bind to the constructor
      - constructor normalization/trimming still applies on deserialization
    Rationale:
      - This verifies the DTO's internal API contract with Jackson: the annotations are part of the class's
        "internals" because without them, the inbound HTTP payload mapping breaks silently.
    """)
    void jackson_deserialize_snakeCase_bindsAndNormalizes() throws Exception {
        String json = """
                {
                  "grant_type": "  PASSWORD  ",
                  "client_id": "  clientA ",
                  "client_secret": "  s3cr3t ",
                  "username": "  alice ",
                  "password": "  pass ",
                  "code": "  code123 ",
                  "redirect_uri": "  https://a/cb ",
                  "refresh_token": "  rt ",
                  "scope": "  read write  "
                }
                """;

        OAuthTokenRequest req = MAPPER.readValue(json, OAuthTokenRequest.class);

        assertEquals("password", req.getGrantType());
        assertEquals("clientA", req.getClientId());
        assertEquals("s3cr3t", req.getClientSecret());
        assertEquals("alice", req.getUsername());
        assertEquals("pass", req.getPassword());
        assertEquals("code123", req.getCode());
        assertEquals("https://a/cb", req.getRedirectUri());
        assertEquals("rt", req.getRefreshToken());
        assertEquals("read write", req.getScope());
    }

    @Test
    @DisplayName("""
    Equality + hashCode: value-based across all fields
    What it tests:
      - equals compares all internal fields
      - hashCode is consistent with equals
    Rationale:
      - Value-based equality is useful for tests, caching, and debugging; if any field is later removed from
        equals/hashCode, subtle bugs appear (e.g., treating requests as identical when they're not).
    """)
    void equalsAndHashCode_valueBasedAcrossAllFields() {
        OAuthTokenRequest a = new OAuthTokenRequest(
                "password", "clientA", "secret", "alice", "pass",
                "code", "https://a/cb", "rt", "read"
        );
        OAuthTokenRequest b = new OAuthTokenRequest(
                "  PASSWORD  ", " clientA ", " secret ", " alice ", " pass ",
                " code ", " https://a/cb ", " rt ", " read "
        );

        // normalization makes them equal
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());

        OAuthTokenRequest c = new OAuthTokenRequest(
                "password", "clientA", "secret", "alice", "pass",
                "code", "https://a/cb", "rt", "write" // different scope
        );
        assertNotEquals(a, c);
    }

    @Test
    @DisplayName("""
    toString safety: does not leak client_secret or password
    What it tests:
      - toString omits sensitive fields (clientSecret, password)
    Rationale:
      - DTOs often get logged during request handling. Leaking secrets/passwords into logs is a serious
        security issue. This test locks in the class's "safe logging" behavior.
    """)
    void toString_doesNotLeakSecretsOrPassword() {
        OAuthTokenRequest req = new OAuthTokenRequest(
                "password",
                "clientA",
                "TOP-SECRET",
                "alice",
                "SUPER-PASSWORD",
                "code123",
                "https://a/cb",
                "rt",
                "read"
        );

        String s = req.toString();

        assertTrue(s.contains("clientId='clientA'"));
        assertTrue(s.contains("username='alice'"));
        assertTrue(s.contains("code='code123'"));

        assertFalse(s.contains("TOP-SECRET"), "client_secret must not appear in toString()");
        assertFalse(s.contains("SUPER-PASSWORD"), "password must not appear in toString()");
        assertFalse(s.toLowerCase().contains("clientsecret="), "toString() should not include clientSecret field name");
        assertFalse(s.toLowerCase().contains("password="), "toString() should not include password field name");
    }

    @Test
    @DisplayName("""
    Jackson round-trip: serialization uses Java property names (not OAuth snake_case)
    What it tests:
      - default ObjectMapper (no naming strategy) will serialize getters as grantType/clientId/... (camelCase)
      - deserialization from snake_case still works due to @JsonProperty on constructor
    Rationale:
      - This clarifies an internal behavior: the DTO is optimized for inbound binding.
        If you later rely on outbound serialization, you'd need explicit @JsonProperty on getters or a naming strategy.
    """)
    void jackson_roundTrip_serializationIsCamelCase_butInboundStillSnakeCase() throws Exception {
        OAuthTokenRequest req = new OAuthTokenRequest(
                "password", "clientA", "secret", "alice", "pass",
                null, null, null, "read"
        );

        String outJson = MAPPER.writeValueAsString(req);

        // default Jackson: uses getters -> camelCase
        assertTrue(outJson.contains("\"grantType\""));
        assertTrue(outJson.contains("\"clientId\""));
        assertFalse(outJson.contains("\"grant_type\""));

        // inbound snake_case still binds (tested above), but demonstrate quickly here too:
        OAuthTokenRequest inbound = MAPPER.readValue(
                "{\"grant_type\":\"PASSWORD\",\"client_id\":\"clientA\"}",
                OAuthTokenRequest.class
        );
        assertEquals("password", inbound.getGrantType());
        assertEquals("clientA", inbound.getClientId());
    }
}