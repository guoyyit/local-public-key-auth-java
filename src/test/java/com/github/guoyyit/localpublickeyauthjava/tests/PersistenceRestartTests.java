package com.github.guoyyit.localpublickeyauthjava.tests;

import com.github.guoyyit.localpublickeyauthjava.Application;
import com.github.guoyyit.localpublickeyauthjava.error.AuthException;
import com.github.guoyyit.localpublickeyauthjava.error.ErrorCode;
import com.github.guoyyit.localpublickeyauthjava.service.AuthService;
import com.github.guoyyit.localpublickeyauthjava.store.AuthStore;
import com.github.guoyyit.localpublickeyauthjava.web.dto.LoginAssertionRequest;
import com.github.guoyyit.localpublickeyauthjava.web.dto.LoginStartRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Persistence and restart recovery tests.
 *
 * <p>Each test boots two independent application contexts over the same data directory:
 * the first writes state and is closed; the second opens it like a restarted process.
 * No in-memory state is shared, so recovery genuinely comes from the file on disk.
 */
class PersistenceRestartTests {

    private static final String ORIGIN = "http://localhost:8080";

    private ConfigurableApplicationContext context(String dir) {
        return new SpringApplicationBuilder(Application.class)
                // Command line args have the highest precedence and reliably override the
                // packaged application.properties.
                .run(
                        "--spring.main.web-application-type=none",
                        "--spring.task.scheduling.enabled=false",
                        "--auth.data-dir=" + dir,
                        "--auth.cleanup.fixed-delay-ms=3600000",
                        "--server.port=0");
    }

    @Test
    void credentialsCountersAndPendingSessionsSurviveRestart() throws Exception {
        String dir = "target/test-data/restart-" + java.util.UUID.randomUUID();
        Files.createDirectories(Path.of(dir));
        SigningKey key1 = SigningKey.ed25519();
        SigningKey key2 = SigningKey.ed25519();

        String pendingSessionId;
        try (var first = context(dir)) {
            AuthService service = first.getBean(AuthService.class);
            register(service, "sam", "cred-sam-1", key1);
            register(service, "sam", "cred-sam-2", key2);
            login(service, "sam", "cred-sam-1", key1, 1);
            login(service, "sam", "cred-sam-1", key1, 2);
            service.disableCredential("sam", "cred-sam-2");
            // An in-flight registration session must also be recoverable.
            pendingSessionId = service.startRegistration(
                    new com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationStartRequest(
                            "sam", ORIGIN)).sessionId();
        }

        try (var restarted = context(dir)) {
            AuthStore store = restarted.getBean(AuthStore.class);
            AuthService service = restarted.getBean(AuthService.class);

            var views = service.listCredentials("sam");
            assertEquals(2, views.size());
            for (var cred : views) {
                if (cred.credentialId().equals("cred-sam-1")) {
                    assertEquals(2, cred.signCount());
                    assertTrue(cred.enabled());
                } else {
                    assertEquals(0, cred.signCount());
                    assertEquals(false, cred.enabled());
                }
            }

            final String sessionId = pendingSessionId;
            boolean sessionPresent = store.read(v -> v.sessions().stream()
                    .anyMatch(s -> s.sessionId().equals(sessionId) && !s.consumed()));
            assertTrue(sessionPresent, "in-flight registration session must survive restart");

            // A non-increasing counter after restart is a clone; counters do not reset.
            var challenge = service.startLogin(new LoginStartRequest("sam", ORIGIN));
            AuthException clone = assertThrows(AuthException.class,
                    () -> service.verifyAssertion(assertRequest(challenge, "sam", "cred-sam-1", key1, 2)));
            assertEquals(ErrorCode.CLONE_DETECTED, clone.errorCode());

            // A strictly increasing counter succeeds and is persisted.
            var challenge2 = service.startLogin(new LoginStartRequest("sam", ORIGIN));
            var response = service.verifyAssertion(assertRequest(challenge2, "sam", "cred-sam-1", key1, 3));
            assertEquals(3, response.signCount());
            assertEquals(3, service.listCredentials("sam").stream()
                    .filter(c -> c.credentialId().equals("cred-sam-1"))
                    .findFirst().orElseThrow().signCount());
        }

        // Re-open one more time: counter=3 must be durable across the second restart too.
        try (var again = context(dir)) {
            AuthService service = again.getBean(AuthService.class);
            assertEquals(3, service.listCredentials("sam").stream()
                    .filter(c -> c.credentialId().equals("cred-sam-1"))
                    .findFirst().orElseThrow().signCount());
        }
    }

    @Test
    void stateFileIsAlwaysACompleteDocumentNoHalfWrites() throws Exception {
        String dir = "target/test-data/restart-" + java.util.UUID.randomUUID();
        Files.createDirectories(Path.of(dir));
        ObjectMapper mapper = new ObjectMapper();
        SigningKey key = SigningKey.ed25519();

        try (var ctx = context(dir)) {
            AuthService service = ctx.getBean(AuthService.class);
            register(service, "tina", "cred-tina-1", key);
            for (int i = 1; i <= 3; i++) {
                login(service, "tina", "cred-tina-1", key, i);
                JsonNode doc = mapper.readTree(Path.of(dir, "auth-state.json").toFile());
                assertNotNull(doc.get("credentials"));
                assertNotNull(doc.get("sessions"));
                assertNotNull(doc.get("challenges"));
                assertEquals(i, doc.get("credentials").get(0).get("signCount").asLong());
            }
            // No temp files are left behind.
            try (var entries = Files.list(Path.of(dir))) {
                assertEquals(1L, entries.count(), "only the single atomic state file must remain");
            }
        }
    }

    private void register(AuthService service, String userId, String credId, SigningKey key) {
        var start = service.startRegistration(
                new com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationStartRequest(userId, ORIGIN));
        byte[] data = ("LOCAL-PK-AUTH-V1:REGISTER\n"
                + "userId=" + userId + "\n"
                + "origin=" + ORIGIN + "\n"
                + "challenge=" + start.challenge() + "\n"
                + "credentialId=" + credId).getBytes(StandardCharsets.UTF_8);
        var response = service.completeRegistration(
                new com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationCompleteRequest(
                        start.sessionId(), userId, ORIGIN, credId, key.algorithm(),
                        key.publicKeyBase64(), key.sign(data)));
        assertEquals("registered", response.status());
    }

    private void login(AuthService service, String userId, String credId, SigningKey key, long counter) {
        var challenge = service.startLogin(new LoginStartRequest(userId, ORIGIN));
        var response = service.verifyAssertion(assertRequest(challenge, userId, credId, key, counter));
        assertEquals(counter, response.signCount());
    }

    private LoginAssertionRequest assertRequest(
            com.github.guoyyit.localpublickeyauthjava.web.dto.LoginStartResponse challenge,
            String userId, String credId, SigningKey key, long counter) {
        byte[] data = ("LOCAL-PK-AUTH-V1:ASSERT\n"
                + "userId=" + userId + "\n"
                + "origin=" + ORIGIN + "\n"
                + "challenge=" + challenge.challenge() + "\n"
                + "credentialId=" + credId + "\n"
                + "signCount=" + counter).getBytes(StandardCharsets.UTF_8);
        return new LoginAssertionRequest(challenge.challengeId(), userId, ORIGIN,
                credId, key.sign(data), counter);
    }
}
