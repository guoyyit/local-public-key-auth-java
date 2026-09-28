package com.github.guoyyit.localpublickeyauthjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end authentication flow tests driven through MockMvc.
 */
@SpringBootTest(properties = {
        "auth.data-dir=target/test-data/flow",
        "auth.registration-ttl-seconds=300",
        "auth.challenge-ttl-seconds=300",
        "auth.cleanup.fixed-delay-ms=3600000"
})
@AutoConfigureMockMvc
class AuthFlowTests {

    private static final String ORIGIN = "http://localhost:8080";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void resetState() throws Exception {
        Path state = Path.of("target/test-data/flow/auth-state.json");
        Files.deleteIfExists(state);
    }

    @Test
    void registerAndLoginWithEd25519() throws Exception {
        SigningKey key = SigningKey.ed25519();
        JsonNode session = startRegistration("alice");
        completeRegistration(session, "alice", "cred-alice-1", key);

        JsonNode challenge = startLogin("alice");
        long count = key.nextCounter();
        JsonNode result = assertLogin(challenge, "alice", "cred-alice-1", key, count);
        assertEquals("authenticated", result.get("status").asText());
        assertEquals(count, result.get("signCount").asLong());

        JsonNode list = listCredentials("alice");
        assertEquals(1, list.size());
        assertEquals(count, list.get(0).get("signCount").asLong());
        assertTrue(list.get(0).get("enabled").asBoolean());
    }

    @Test
    void registerAndLoginWithEcP256() throws Exception {
        SigningKey key = SigningKey.ecP256();
        JsonNode session = startRegistration("bob");
        completeRegistration(session, "bob", "cred-bob-ec", key);

        JsonNode challenge = startLogin("bob");
        JsonNode result = assertLogin(challenge, "bob", "cred-bob-ec", key, key.nextCounter());
        assertEquals("authenticated", result.get("status").asText());
    }

    @Test
    void multipleCredentialsForSameUserAreIndependent() throws Exception {
        SigningKey key1 = SigningKey.ed25519();
        SigningKey key2 = SigningKey.ed25519();
        completeRegistration(startRegistration("carol"), "carol", "cred-carol-1", key1);
        completeRegistration(startRegistration("carol"), "carol", "cred-carol-2", key2);

        JsonNode list = listCredentials("carol");
        assertEquals(2, list.size());

        // Login with the second credential.
        JsonNode result = assertLogin(startLogin("carol"), "carol", "cred-carol-2", key2, key2.nextCounter());
        assertEquals("authenticated", result.get("status").asText());

        // Disable the first credential; it must no longer work.
        mockMvc.perform(delete("/api/auth/users/carol/credentials/cred-carol-1"))
                .andExpect(status().isNoContent());
        JsonNode challenge = startLogin("carol");
        errorBody(postAssert(challenge, "carol", "cred-carol-1", key1, key1.nextCounter()), 403, "CREDENTIAL_DISABLED");

        // The other credential keeps working and keeps its own counter.
        result = assertLogin(startLogin("carol"), "carol", "cred-carol-2", key2, key2.nextCounter());
        assertEquals("authenticated", result.get("status").asText());

        list = listCredentials("carol");
        int enabled = 0;
        for (JsonNode cred : list) {
            if (cred.get("enabled").asBoolean()) {
                enabled++;
            }
        }
        assertEquals(1, enabled);
    }

    @Test
    void rejectsBadRegistrationSignature() throws Exception {
        SigningKey good = SigningKey.ed25519();
        SigningKey attacker = SigningKey.ed25519();
        JsonNode session = startRegistration("dave");
        // Attacker signs with its own key but claims the victim public key.
        String body = registrationCompleteBody(session, "dave", "cred-dave-1", good, attacker);
        errorBody(postJson("/api/auth/register/complete", body), 401, "SIGNATURE_INVALID");

        // Session must still be usable (failed validation writes nothing).
        completeRegistration(session, "dave", "cred-dave-1", good);
    }

    @Test
    void failedRegistrationLeavesNoStateBehind() throws Exception {
        SigningKey good = SigningKey.ed25519();
        SigningKey attacker = SigningKey.ed25519();
        JsonNode session = startRegistration("nancy");

        // Fail the same registration in several different ways; none may write a credential.
        errorBody(postJson("/api/auth/register/complete",
                registrationCompleteBody(session, "nancy", "cred-nancy-x", good, attacker)),
                401, "SIGNATURE_INVALID");
        errorBody(postJson("/api/auth/register/complete",
                registrationCompleteBody(session, "nancy", "cred-nancy-x", good,
                        SigningKey.ed25519(), "https://evil.example")),
                400, "INVALID_ORIGIN");
        assertEquals(0, listCredentials("nancy").size(), "failed registration must not persist a credential");

        // The session survived untouched and can complete the registration properly.
        completeRegistration(session, "nancy", "cred-nancy-x", good);
        assertEquals(1, listCredentials("nancy").size());
    }

    @Test
    void rejectsWrongOriginOnRegistration() throws Exception {
        SigningKey key = SigningKey.ed25519();
        JsonNode session = startRegistration("erin");
        String body = registrationCompleteBody(session, "erin", "cred-erin-1", key, "https://evil.example");
        errorBody(postJson("/api/auth/register/complete", body), 400, "INVALID_ORIGIN");
    }

    @Test
    void rejectsUnallowedOriginOnStart() throws Exception {
        errorBody(postJson("/api/auth/register/start",
                Map.of("userId", "frank", "origin", "https://evil.example")), 400, "INVALID_ORIGIN");
    }

    @Test
    void rejectsUserMismatchOnAssertion() throws Exception {
        SigningKey key = SigningKey.ed25519();
        completeRegistration(startRegistration("grace"), "grace", "cred-grace-1", key);
        JsonNode challenge = startLogin("grace");
        // Bind the assertion to another user id.
        errorBody(postAssert(challenge, "mallory", "cred-grace-1", key, key.nextCounter()),
                403, "USER_MISMATCH");
    }

    @Test
    void rejectsReplayedAssertion() throws Exception {
        SigningKey key = SigningKey.ed25519();
        completeRegistration(startRegistration("heidi"), "heidi", "cred-heidi-1", key);
        JsonNode challenge = startLogin("heidi");
        long count = key.nextCounter();
        assertLogin(challenge, "heidi", "cred-heidi-1", key, count);
        // Same challenge + same signature + counter again => replay.
        errorBody(postAssert(challenge, "heidi", "cred-heidi-1", key, count), 409, "CHALLENGE_REPLAY");
    }

    @Test
    void rejectsClonedOrRewoundCounter() throws Exception {
        SigningKey key = SigningKey.ed25519();
        completeRegistration(startRegistration("ivan"), "ivan", "cred-ivan-1", key);

        assertLogin(startLogin("ivan"), "ivan", "cred-ivan-1", key, 5);
        // Cloned authenticator with lower counter, valid signature -> clone detected.
        errorBody(postAssert(startLogin("ivan"), "ivan", "cred-ivan-1", key, 5), 409, "CLONE_DETECTED");
        errorBody(postAssert(startLogin("ivan"), "ivan", "cred-ivan-1", key, 3), 409, "CLONE_DETECTED");

        // Legitimate advancing counter still works.
        assertLogin(startLogin("ivan"), "ivan", "cred-ivan-1", key, 6);
    }

    @Test
    void rejectsBadAssertionSignature() throws Exception {
        SigningKey key = SigningKey.ed25519();
        SigningKey attacker = SigningKey.ed25519();
        completeRegistration(startRegistration("judy"), "judy", "cred-judy-1", key);
        JsonNode challenge = startLogin("judy");
        long count = key.nextCounter();
        String body = objectMapper.writeValueAsString(java.util.Map.of(
                "challengeId", challenge.get("challengeId").asText(),
                "userId", "judy",
                "origin", ORIGIN,
                "credentialId", "cred-judy-1",
                "signCount", count,
                "signature", attacker.sign(canonicalAssertion(challenge, "judy", "cred-judy-1", count))));
        errorBody(postRawJson("/api/auth/login/assert", body), 401, "SIGNATURE_INVALID");

        // Challenge survives a signature failure and can still be answered correctly.
        assertLogin(challenge, "judy", "cred-judy-1", key, count);
    }

    @Test
    void rejectsUnknownCredential() throws Exception {
        SigningKey key = SigningKey.ed25519();
        completeRegistration(startRegistration("kate"), "kate", "cred-kate-1", key);
        errorBody(postAssert(startLogin("kate"), "kate", "cred-other", key, 1),
                404, "UNKNOWN_CREDENTIAL");
    }

    @Test
    void rejectsDuplicateCredentialId() throws Exception {
        SigningKey key1 = SigningKey.ed25519();
        SigningKey key2 = SigningKey.ed25519();
        completeRegistration(startRegistration("leo"), "leo", "dup-id", key1);
        JsonNode session = startRegistration("leo");
        String body = registrationCompleteBody(session, "leo", "dup-id", key2);
        errorBody(postJson("/api/auth/register/complete", body), 409, "CREDENTIAL_EXISTS");
    }

    @Test
    void rejectsMalformedPublicKey() throws Exception {
        JsonNode session = startRegistration("mike");
        String body = objectMapper.writeValueAsString(Map.of(
                "sessionId", session.get("sessionId").asText(),
                "userId", "mike",
                "origin", ORIGIN,
                "credentialId", "cred-mike-1",
                "algorithm", "Ed25519",
                "publicKey", "not-base64!!",
                "signature", "AAAA"));
        errorBody(postJson("/api/auth/register/complete", body), 400, "MALFORMED_CREDENTIAL");
    }

    // ---------------- helpers ----------------

    private JsonNode startRegistration(String userId) throws Exception {
        return json(postJson("/api/auth/register/start", Map.of("userId", userId, "origin", ORIGIN)));
    }

    private void completeRegistration(JsonNode session, String userId, String credId, SigningKey key) throws Exception {
        String body = registrationCompleteBody(session, userId, credId, key);
        JsonNode response = json(postJson("/api/auth/register/complete", body));
        assertEquals("registered", response.get("status").asText());
    }

    private String registrationCompleteBody(JsonNode session, String userId, String credId, SigningKey key) {
        return registrationCompleteBody(session, userId, credId, key, key, ORIGIN);
    }

    private String registrationCompleteBody(JsonNode session, String userId, String credId,
                                            SigningKey publicKeyHolder, SigningKey signer) {
        return registrationCompleteBody(session, userId, credId, publicKeyHolder, signer, ORIGIN);
    }

    private String registrationCompleteBody(JsonNode session, String userId, String credId,
                                            SigningKey publicKeyHolder, String origin) {
        return registrationCompleteBody(session, userId, credId, publicKeyHolder, publicKeyHolder, origin);
    }

    private String registrationCompleteBody(JsonNode session, String userId, String credId,
                                            SigningKey publicKeyHolder, SigningKey signer, String origin) {
        try {
            String challenge = session.get("challenge").asText();
            byte[] data = ("LOCAL-PK-AUTH-V1:REGISTER\n"
                    + "userId=" + userId + "\n"
                    + "origin=" + origin + "\n"
                    + "challenge=" + challenge + "\n"
                    + "credentialId=" + credId).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            return objectMapper.writeValueAsString(Map.of(
                    "sessionId", session.get("sessionId").asText(),
                    "userId", userId,
                    "origin", origin,
                    "credentialId", credId,
                    "algorithm", publicKeyHolder.algorithm(),
                    "publicKey", publicKeyHolder.publicKeyBase64(),
                    "signature", signer.sign(data)));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private JsonNode startLogin(String userId) throws Exception {
        return json(postJson("/api/auth/login/start", Map.of("userId", userId, "origin", ORIGIN)));
    }

    private JsonNode assertLogin(JsonNode challenge, String userId, String credId,
                                 SigningKey key, long count) throws Exception {
        return json(postAssert(challenge, userId, credId, key, count));
    }

    private org.springframework.test.web.servlet.MvcResult postAssert(JsonNode challenge, String userId,
            String credId, SigningKey key, long count) throws Exception {
        String body = objectMapper.writeValueAsString(java.util.Map.of(
                "challengeId", challenge.get("challengeId").asText(),
                "userId", userId,
                "origin", ORIGIN,
                "credentialId", credId,
                "signCount", count,
                "signature", key.sign(canonicalAssertion(challenge, userId, credId, count))));
        return postRawJson("/api/auth/login/assert", body);
    }

    private byte[] canonicalAssertion(JsonNode challenge, String userId, String credId, long count) {
        String challengeValue = challenge.get("challenge").asText();
        return ("LOCAL-PK-AUTH-V1:ASSERT\n"
                + "userId=" + userId + "\n"
                + "origin=" + ORIGIN + "\n"
                + "challenge=" + challengeValue + "\n"
                + "credentialId=" + credId + "\n"
                + "signCount=" + count).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private JsonNode listCredentials(String userId) throws Exception {
        return objectMapper.readTree(
                mockMvc.perform(get("/api/auth/users/" + userId + "/credentials"))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString());
    }

    private org.springframework.test.web.servlet.MvcResult postJson(String url, Map<?, ?> body) throws Exception {
        return postRawJson(url, objectMapper.writeValueAsString(body));
    }

    private org.springframework.test.web.servlet.MvcResult postJson(String url, String body) throws Exception {
        return postRawJson(url, body);
    }

    private org.springframework.test.web.servlet.MvcResult postRawJson(String url, String body) throws Exception {
        return mockMvc.perform(post(url)
                        .contentType("application/json")
                        .content(body))
                .andReturn();
    }

    private JsonNode json(org.springframework.test.web.servlet.MvcResult result) throws Exception {
        assertEquals(200, result.getResponse().getStatus(),
                result.getResponse().getStatus() + ": " + result.getResponse().getContentAsString());
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private void errorBody(org.springframework.test.web.servlet.MvcResult result, int status, String code) throws Exception {
        assertEquals(status, result.getResponse().getStatus(),
                result.getResponse().getContentAsString());
        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(code, node.get("error").asText());
    }
}
