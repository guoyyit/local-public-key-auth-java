package com.github.guoyyit.localpublickeyauthjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Expiry and reclamation tests for registration sessions and login challenges.
 */
@SpringBootTest(properties = {
        "auth.data-dir=target/test-data/expiry",
        "auth.registration-ttl-seconds=1",
        "auth.challenge-ttl-seconds=1",
        "auth.counter-gap-timeout-ms=50",
        "auth.cleanup.fixed-delay-ms=3600000"
})
@AutoConfigureMockMvc
class ExpiryTests {

    private static final String ORIGIN = "http://localhost:8080";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private com.github.guoyyit.localpublickeyauthjava.service.AuthService authService;

    @BeforeEach
    void resetState() throws Exception {
        Files.deleteIfExists(Path.of("target/test-data/expiry/auth-state.json"));
    }

    @Test
    void expiredRegistrationSessionIsRejectedAndReclaimed() throws Exception {
        SigningKey key = SigningKey.ed25519();
        JsonNode session = start("nina");
        Thread.sleep(1100);

        String body = completeBody(session, "nina", "cred-nina-1", key);
        JsonNode error = error(postRaw(body), 410, "SESSION_EXPIRED");
        assertEquals("registration session has expired", error.get("message").asText());

        // Purge reclaims the expired session; subsequent use reports it as gone.
        authService.purgeExpired();
        error(postRaw(body), 410, "SESSION_NOT_FOUND");
    }

    @Test
    void expiredLoginChallengeIsRejectedAndReclaimed() throws Exception {
        SigningKey key = SigningKey.ed25519();
        JsonNode session = start("oscar");
        JsonNode regOk = objectMapper.readTree(postRaw(completeBody(session, "oscar", "cred-oscar-1", key))
                .getResponse().getContentAsString());
        assertEquals("registered", regOk.get("status").asText());

        JsonNode challenge = objectMapper.readTree(postJson("/api/auth/login/start",
                Map.of("userId", "oscar", "origin", ORIGIN)).getResponse().getContentAsString());
        Thread.sleep(1100);

        String body = assertBody(challenge, "oscar", "cred-oscar-1", key, 1);
        error(postRaw(body), 410, "CHALLENGE_EXPIRED");
        authService.purgeExpired();
        error(postRaw(body), 410, "CHALLENGE_NOT_FOUND");
    }

    @Test
    void concurrentRegistrationsForSameUserGetIndependentChallenges() throws Exception {
        JsonNode session1 = start("peggy");
        JsonNode session2 = start("peggy");
        SigningKey key1 = SigningKey.ed25519();
        SigningKey key2 = SigningKey.ed25519();

        // Completing one does not consume or overwrite the other.
        JsonNode ok = objectMapper.readTree(
                postRaw(completeBody(session2, "peggy", "cred-peggy-2", key2))
                        .getResponse().getContentAsString());
        assertEquals("registered", ok.get("status").asText());

        JsonNode ok2 = objectMapper.readTree(
                postRaw(completeBody(session1, "peggy", "cred-peggy-1", key1))
                        .getResponse().getContentAsString());
        assertEquals("registered", ok2.get("status").asText());

        // Each session is single use.
        error(postRaw(completeBody(session1, "peggy", "cred-peggy-3", SigningKey.ed25519())),
                409, "SESSION_ALREADY_USED");
    }

    private JsonNode start(String userId) throws Exception {
        return objectMapper.readTree(postJson("/api/auth/register/start",
                Map.of("userId", userId, "origin", ORIGIN)).getResponse().getContentAsString());
    }

    private String completeBody(JsonNode session, String userId, String credId, SigningKey key) throws Exception {
        byte[] data = ("LOCAL-PK-AUTH-V1:REGISTER\n"
                + "userId=" + userId + "\n"
                + "origin=" + ORIGIN + "\n"
                + "challenge=" + session.get("challenge").asText() + "\n"
                + "credentialId=" + credId).getBytes(StandardCharsets.UTF_8);
        return objectMapper.writeValueAsString(Map.of(
                "sessionId", session.get("sessionId").asText(),
                "userId", userId,
                "origin", ORIGIN,
                "credentialId", credId,
                "algorithm", key.algorithm(),
                "publicKey", key.publicKeyBase64(),
                "signature", key.sign(data)));
    }

    private String assertBody(JsonNode challenge, String userId, String credId, SigningKey key, long count)
            throws Exception {
        byte[] data = ("LOCAL-PK-AUTH-V1:ASSERT\n"
                + "userId=" + userId + "\n"
                + "origin=" + ORIGIN + "\n"
                + "challenge=" + challenge.get("challenge").asText() + "\n"
                + "credentialId=" + credId + "\n"
                + "signCount=" + count).getBytes(StandardCharsets.UTF_8);
        return objectMapper.writeValueAsString(Map.of(
                "challengeId", challenge.get("challengeId").asText(),
                "userId", userId,
                "origin", ORIGIN,
                "credentialId", credId,
                "signCount", count,
                "signature", key.sign(data)));
    }

    private org.springframework.test.web.servlet.MvcResult postJson(String url, Map<?, ?> body) throws Exception {
        return doPost(url, objectMapper.writeValueAsString(body));
    }

    private org.springframework.test.web.servlet.MvcResult postRaw(String body) throws Exception {
        return doPost(body.contains("sessionId") ? "/api/auth/register/complete" : "/api/auth/login/assert", body);
    }

    private org.springframework.test.web.servlet.MvcResult doPost(String url, String body) throws Exception {
        return mockMvc.perform(post(url).contentType("application/json").content(body)).andReturn();
    }

    private JsonNode error(org.springframework.test.web.servlet.MvcResult result, int status, String code)
            throws Exception {
        assertEquals(status, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(code, node.get("error").asText());
        return node;
    }
}
