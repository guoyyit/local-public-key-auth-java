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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Concurrent assertion tests for monotonic counter handling.
 */
@SpringBootTest(properties = {
        "auth.data-dir=target/test-data/concurrent",
        "auth.registration-ttl-seconds=300",
        "auth.challenge-ttl-seconds=300",
        "auth.counter-gap-timeout-ms=5000",
        "auth.cleanup.fixed-delay-ms=3600000"
})
@AutoConfigureMockMvc
class ConcurrentAssertionTests {

    private static final String ORIGIN = "http://localhost:8080";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    private SigningKey key;
    private String user;
    private String credentialId;

    @BeforeEach
    void resetState() throws Exception {
        Files.deleteIfExists(Path.of("target/test-data/concurrent/auth-state.json"));
        this.key = SigningKey.ed25519();
    }

    @Test
    void outOfOrderConcurrentAssertionsAllSucceedWithNoFalseClone() throws Exception {
        register();
        int n = 20;
        // Each thread gets its own challenge and a unique successive counter, submitted in
        // deliberately reversed order.
        List<Callable<Integer>> tasks = new ArrayList<>();
        for (int i = n; i >= 1; i--) {
            final long counter = i;
            final JsonNode challenge = startLogin();
            tasks.add(() -> {
                String body = assertBody(challenge, counter);
                int status = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                .post("/api/auth/login/assert")
                                .contentType("application/json")
                                .content(body))
                        .andReturn().getResponse().getStatus();
                return status;
            });
        }

        // One thread per task: GAP waiters park without holding the store lock, but a pool
        // smaller than the number of waiting tasks could starve the committers. Real servers
        // have far more request threads than concurrent assertions of one credential.
        ExecutorService pool = Executors.newCachedThreadPool();
        try {
            List<Future<Integer>> futures = pool.invokeAll(tasks, 60, TimeUnit.SECONDS);
            for (Future<Integer> future : futures) {
                assertEquals(200, future.get(), "concurrent valid assertion must not be rejected");
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(n, currentCredential().get("signCount").asLong(),
                "counter must atomically reach the highest value");
    }

    @Test
    void parallelAssertionsWithSameCounterDetectCloneForAllButOne() throws Exception {
        register();
        // Multiple assertions using the same counter cannot all advance it: at most one commits
        // and the rest are clone/replay rejections. The stored counter is still consistent.
        int n = 10;
        long counter = 5;
        List<Callable<Integer>> tasks = new ArrayList<>();
        List<JsonNode> challenges = Collections.synchronizedList(new ArrayList<>());
        for (int i = 0; i < n; i++) {
            challenges.add(startLogin());
        }
        for (JsonNode challenge : challenges) {
            tasks.add(() -> mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                            .post("/api/auth/login/assert")
                            .contentType("application/json")
                            .content(assertBody(challenge, counter)))
                    .andReturn().getResponse().getStatus());
        }
        ExecutorService pool = Executors.newCachedThreadPool();
        int ok = 0;
        int rejected = 0;
        try {
            for (Future<Integer> future : pool.invokeAll(tasks, 30, TimeUnit.SECONDS)) {
                int status = future.get();
                if (status == 200) {
                    ok++;
                } else {
                    assertEquals(409, status);
                    rejected++;
                }
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, ok, "exactly one assertion for a given counter value may commit");
        assertEquals(n - 1, rejected);
        assertEquals(counter, currentCredential().get("signCount").asLong());

        // A subsequent strictly increasing assertion works fine: no permanent damage.
        JsonNode challenge = startLogin();
        int status = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/auth/login/assert")
                        .contentType("application/json")
                        .content(assertBody(challenge, counter + 1)))
                .andReturn().getResponse().getStatus();
        assertEquals(200, status);
        assertTrue(true);
    }

    // ---------------- helpers ----------------

    private void register() throws Exception {
        this.user = "user-" + java.util.UUID.randomUUID();
        this.credentialId = "cred-" + java.util.UUID.randomUUID();
        JsonNode session = objectMapper.readTree(mockMvc.perform(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/auth/register/start")
                                .contentType("application/json")
                                .content(objectMapper.writeValueAsString(Map.of("userId", user, "origin", ORIGIN))))
                .andReturn().getResponse().getContentAsString());
        byte[] data = ("LOCAL-PK-AUTH-V1:REGISTER\n"
                + "userId=" + user + "\n"
                + "origin=" + ORIGIN + "\n"
                + "challenge=" + session.get("challenge").asText() + "\n"
                + "credentialId=" + credentialId).getBytes(StandardCharsets.UTF_8);
        String body = objectMapper.writeValueAsString(Map.of(
                "sessionId", session.get("sessionId").asText(),
                "userId", user,
                "origin", ORIGIN,
                "credentialId", credentialId,
                "algorithm", key.algorithm(),
                "publicKey", key.publicKeyBase64(),
                "signature", key.sign(data)));
        int status = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/auth/register/complete")
                        .contentType("application/json").content(body))
                .andReturn().getResponse().getStatus();
        assertEquals(200, status);
    }

    private JsonNode startLogin() throws Exception {
        return objectMapper.readTree(mockMvc.perform(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/auth/login/start")
                                .contentType("application/json")
                                .content(objectMapper.writeValueAsString(Map.of("userId", user, "origin", ORIGIN))))
                .andReturn().getResponse().getContentAsString());
    }

    private String assertBody(JsonNode challenge, long counter) throws Exception {
        byte[] data = ("LOCAL-PK-AUTH-V1:ASSERT\n"
                + "userId=" + user + "\n"
                + "origin=" + ORIGIN + "\n"
                + "challenge=" + challenge.get("challenge").asText() + "\n"
                + "credentialId=" + credentialId + "\n"
                + "signCount=" + counter).getBytes(StandardCharsets.UTF_8);
        return objectMapper.writeValueAsString(Map.of(
                "challengeId", challenge.get("challengeId").asText(),
                "userId", user,
                "origin", ORIGIN,
                "credentialId", credentialId,
                "signCount", counter,
                "signature", key.sign(data)));
    }

    private JsonNode currentCredential() throws Exception {
        var response = mockMvc.perform(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                .get("/api/auth/users/" + user + "/credentials"))
                .andReturn().getResponse();
        assertEquals(200, response.getStatus(), response.getContentAsString());
        JsonNode list = objectMapper.readTree(response.getContentAsString());
        for (JsonNode node : list) {
            if (credentialId.equals(node.get("credentialId").asText())) {
                return node;
            }
        }
        throw new IllegalStateException("test credential not found: " + list);
    }
}
