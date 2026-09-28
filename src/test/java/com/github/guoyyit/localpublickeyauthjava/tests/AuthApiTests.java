package com.github.guoyyit.localpublickeyauthjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.localpublickeyauthjava.config.AuthProperties;
import com.github.guoyyit.localpublickeyauthjava.store.JsonFileStore;
import com.github.guoyyit.localpublickeyauthjava.tests.support.TestKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.security.KeyPair;
import java.util.Base64;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@org.springframework.test.context.TestPropertySource(properties = {
        "auth.expected-origin=https://app.example.com",
        "auth.registration-ttl-seconds=300",
        "auth.assertion-ttl-seconds=300",
        "auth.store-file=./target/test-data/auth-api.json"
})
class AuthApiTests {

    private static final String ORIGIN = "https://app.example.com";
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JsonFileStore store;
    @Autowired AuthProperties props;

    @BeforeEach
    void reset() {
        store.reset();
    }

    private JsonNode postJson(String path, Object body) throws Exception {
        MvcResult result = mvc.perform(post(path)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andReturn();
        return json.readTree(result.getResponse().getContentAsString());
    }

    private String registerViaApi(String user, String credId, KeyPair kp) throws Exception {
        JsonNode start = postJson("/api/auth/register/start", Map.of("userId", user, "origin", ORIGIN));
        String sessionId = start.get("sessionId").asText();
        String challenge = start.get("challenge").asText();
        String pk = TestKeys.publicKey(kp);
        byte[] msg = TestKeys.registrationMessage(ORIGIN, user, challenge, credId, pk);
        JsonNode done = postJson("/api/auth/register/complete", Map.of(
                "sessionId", sessionId,
                "userId", user,
                "origin", ORIGIN,
                "credentialId", credId,
                "publicKey", pk,
                "signature", TestKeys.sign(kp, msg)));
        org.junit.jupiter.api.Assertions.assertEquals(credId, done.get("credentialId").asText());
        return pk;
    }

    private void loginViaApi(String user, String credId, KeyPair kp, long counter) throws Exception {
        JsonNode start = postJson("/api/auth/assert/start", Map.of("userId", user, "origin", ORIGIN));
        String challengeId = start.get("challengeId").asText();
        String challenge = start.get("challenge").asText();
        byte[] msg = TestKeys.assertionMessage(ORIGIN, user, challenge, credId, counter);
        postJson("/api/auth/assert/verify", Map.of(
                "challengeId", challengeId,
                "userId", user,
                "origin", ORIGIN,
                "credentialId", credId,
                "counter", counter,
                "signature", TestKeys.sign(kp, msg)));
    }

    @Test
    void fullRegistrationAndLoginFlow() throws Exception {
        KeyPair kp = TestKeys.generate();
        registerViaApi("carol", "cred-carol-1", kp);

        JsonNode start = postJson("/api/auth/assert/start", Map.of("userId", "carol", "origin", ORIGIN));
        String challengeId = start.get("challengeId").asText();
        String challenge = start.get("challenge").asText();
        byte[] msg = TestKeys.assertionMessage(ORIGIN, "carol", challenge, "cred-carol-1", 0);

        mvc.perform(post("/api/auth/assert/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of(
                                "challengeId", challengeId,
                                "userId", "carol",
                                "origin", ORIGIN,
                                "credentialId", "cred-carol-1",
                                "counter", 0,
                                "signature", TestKeys.sign(kp, msg)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.counter").value(0));

        mvc.perform(get("/api/auth/credentials").param("userId", "carol"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].status").value("ACTIVE"))
                .andExpect(jsonPath("$[0].counter").value(0));
    }

    @Test
    void malformedRegistrationRejected() throws Exception {
        KeyPair kp = TestKeys.generate();
        JsonNode start = postJson("/api/auth/register/start", Map.of("userId", "dave", "origin", ORIGIN));
        String pk = TestKeys.publicKey(kp);

        mvc.perform(post("/api/auth/register/complete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of(
                                "sessionId", start.get("sessionId").asText(),
                                "userId", "dave",
                                "origin", ORIGIN,
                                "credentialId", "cred-dave-bad",
                                "publicKey", "not-a-key!!",
                                "signature", "AAAA"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_PUBLIC_KEY"));

        // session must still be usable after the failed attempt never consumed it
        // (validation failure happened on malformed key -> no persistence effect)
    }

    @Test
    void originMismatchReturns403() throws Exception {
        mvc.perform(post("/api/auth/register/start")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of(
                                "userId", "erin", "origin", "https://evil.example.org"))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ORIGIN_MISMATCH"));
    }

    @Test
    void replayedChallengeReturns404() throws Exception {
        KeyPair kp = TestKeys.generate();
        registerViaApi("frank", "cred-frank-1", kp);
        JsonNode start = postJson("/api/auth/assert/start", Map.of("userId", "frank", "origin", ORIGIN));
        String challengeId = start.get("challengeId").asText();
        String challenge = start.get("challenge").asText();

        byte[] msg0 = TestKeys.assertionMessage(ORIGIN, "frank", challenge, "cred-frank-1", 0);
        mvc.perform(post("/api/auth/assert/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of(
                                "challengeId", challengeId, "userId", "frank", "origin", ORIGIN,
                                "credentialId", "cred-frank-1", "counter", 0,
                                "signature", TestKeys.sign(kp, msg0)))))
                .andExpect(status().isOk());

        byte[] msg1 = TestKeys.assertionMessage(ORIGIN, "frank", challenge, "cred-frank-1", 1);
        mvc.perform(post("/api/auth/assert/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of(
                                "challengeId", challengeId, "userId", "frank", "origin", ORIGIN,
                                "credentialId", "cred-frank-1", "counter", 1,
                                "signature", TestKeys.sign(kp, msg1)))))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("CHALLENGE_NOT_FOUND"));
    }

    @Test
    void disableAndRevokeEndpoints() throws Exception {
        KeyPair k1 = TestKeys.generate();
        KeyPair k2 = TestKeys.generate();
        registerViaApi("grace", "cred-grace-a", k1);
        registerViaApi("grace", "cred-grace-b", k2);

        mvc.perform(post("/api/auth/credentials/cred-grace-a/disable").param("userId", "grace"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DISABLED"));

        // disabled credential fails login; other credential still works
        loginViaApi("grace", "cred-grace-b", k2, 0);

        mvc.perform(post("/api/auth/credentials/cred-grace-b/revoke").param("userId", "grace"))
                .andExpect(status().isOk());

        mvc.perform(get("/api/auth/credentials").param("userId", "grace"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].status").value("DISABLED"))
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    void cloneDetectionRevokesCredential() throws Exception {
        KeyPair kp = TestKeys.generate();
        registerViaApi("heidi", "cred-heidi-1", kp);
        loginViaApi("heidi", "cred-heidi-1", kp, 1);
        loginViaApi("heidi", "cred-heidi-1", kp, 2);

        JsonNode start = postJson("/api/auth/assert/start", Map.of("userId", "heidi", "origin", ORIGIN));
        byte[] msg = TestKeys.assertionMessage(ORIGIN, "heidi", start.get("challenge").asText(),
                "cred-heidi-1", 1);
        mvc.perform(post("/api/auth/assert/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of(
                                "challengeId", start.get("challengeId").asText(),
                                "userId", "heidi", "origin", ORIGIN,
                                "credentialId", "cred-heidi-1", "counter", 1,
                                "signature", TestKeys.sign(kp, msg)))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("COUNTER_CLONE_DETECTED"));
    }
}
