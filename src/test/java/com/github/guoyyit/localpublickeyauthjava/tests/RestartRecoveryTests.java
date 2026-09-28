package com.github.guoyyit.localpublickeyauthjava.tests;

import com.github.guoyyit.localpublickeyauthjava.Application;
import com.github.guoyyit.localpublickeyauthjava.model.ApiException;
import com.github.guoyyit.localpublickeyauthjava.model.AssertionChallenge;
import com.github.guoyyit.localpublickeyauthjava.model.Credential;
import com.github.guoyyit.localpublickeyauthjava.model.CredentialStatus;
import com.github.guoyyit.localpublickeyauthjava.model.ErrorCode;
import com.github.guoyyit.localpublickeyauthjava.model.RegistrationSession;
import com.github.guoyyit.localpublickeyauthjava.service.AuthenticationService;
import com.github.guoyyit.localpublickeyauthjava.service.ChallengeService;
import com.github.guoyyit.localpublickeyauthjava.service.CredentialService;
import com.github.guoyyit.localpublickeyauthjava.tests.support.TestKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.boot.builder.SpringApplicationBuilder;

import java.nio.file.Path;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Boots two independent Spring contexts against the same on-disk store to
 * prove credentials, counters and in-flight sessions survive a restart.
 */
class RestartRecoveryTests {

    private static final String ORIGIN = "https://app.example.com";

    /** A small standalone context handle with the beans under test. */
    static final class Context implements AutoCloseable {
        final ConfigurableApplicationContext ctx;
        final ChallengeService challenges;
        final CredentialService credentials;
        final AuthenticationService authentication;

        Context(Path storeFile) {
            this.ctx = new SpringApplicationBuilder(Application.class)
                    .web(org.springframework.boot.WebApplicationType.NONE)
                    .run(
                            "--auth.expected-origin=" + ORIGIN,
                            "--auth.registration-ttl-seconds=300",
                            "--auth.assertion-ttl-seconds=300",
                            "--auth.store-file=" + storeFile.toAbsolutePath());
            this.challenges = ctx.getBean(ChallengeService.class);
            this.credentials = ctx.getBean(CredentialService.class);
            this.authentication = ctx.getBean(AuthenticationService.class);
        }

        @Override
        public void close() {
            ctx.close();
        }
    }

    @Test
    void stateSurvivesRestart(@TempDir Path dir) {
        Path storeFile = dir.resolve("auth.json");
        KeyPair kp = TestKeys.generate();
        String pk = TestKeys.publicKey(kp);
        String pendingSessionId;
        String pendingChallenge;
        String consumedSessionId;
        String assertionChallengeId;
        String assertionChallenge;

        // ---- first boot: register, log in twice, leave sessions pending ----
        try (Context c = new Context(storeFile)) {
            RegistrationSession s = c.challenges.createRegistration("alice", ORIGIN);
            consumedSessionId = s.getSessionId();
            byte[] regMsg = TestKeys.registrationMessage(ORIGIN, "alice", s.getChallenge(),
                    "cred-restore-1", pk);
            c.credentials.register("alice", s.getSessionId(), ORIGIN, "cred-restore-1", pk,
                    TestKeys.sign(kp, regMsg));

            AssertionChallenge a1 = c.challenges.createAssertion("alice", ORIGIN);
            c.authentication.authenticate("alice", a1.getChallengeId(), "cred-restore-1", 0,
                    TestKeys.sign(kp, TestKeys.assertionMessage(ORIGIN, "alice",
                            a1.getChallenge(), "cred-restore-1", 0)), ORIGIN);

            AssertionChallenge a2 = c.challenges.createAssertion("alice", ORIGIN);
            c.authentication.authenticate("alice", a2.getChallengeId(), "cred-restore-1", 1,
                    TestKeys.sign(kp, TestKeys.assertionMessage(ORIGIN, "alice",
                            a2.getChallenge(), "cred-restore-1", 1)), ORIGIN);
            assertEquals(1, c.credentials.findActive("alice", "cred-restore-1").getCounter());

            // disable via lifecycle before restart
            RegistrationSession pending = c.challenges.createRegistration("alice", ORIGIN);
            pendingSessionId = pending.getSessionId();
            pendingChallenge = pending.getChallenge();

            AssertionChallenge a3 = c.challenges.createAssertion("alice", ORIGIN);
            assertionChallengeId = a3.getChallengeId();
            assertionChallenge = a3.getChallenge();
        }

        // ---- second boot from the same file ----
        try (Context c = new Context(storeFile)) {
            Credential restored = c.credentials.findActive("alice", "cred-restore-1");
            assertNotNull(restored);
            assertEquals(CredentialStatus.ACTIVE, restored.getStatus());
            assertEquals(1, restored.getCounter());
            assertEquals(pk, restored.getPublicKey());

            // login keeps working and counter continues monotonically
            AssertionChallenge a4 = c.challenges.createAssertion("alice", ORIGIN);
            assertTrue(c.authentication.authenticate("alice", a4.getChallengeId(), "cred-restore-1", 2,
                    TestKeys.sign(kp, TestKeys.assertionMessage(ORIGIN, "alice", a4.getChallenge(),
                            "cred-restore-1", 2)), ORIGIN));

            // pending registration survives and completes atomically
            c.credentials.register("alice", pendingSessionId, ORIGIN, "cred-restore-2", pk,
                    TestKeys.sign(kp, TestKeys.registrationMessage(ORIGIN, "alice",
                            pendingChallenge, "cred-restore-2", pk)));
            assertEquals(2, c.credentials.list("alice").size());

            // session consumed before restart must not resurrect
            ApiException ex = assertThrows(ApiException.class, () ->
                    c.credentials.register("alice", consumedSessionId, ORIGIN, "cred-restore-x", pk, "x"));
            assertEquals(ErrorCode.CHALLENGE_NOT_FOUND, ex.getCode());

            // pending assertion challenge survives and is single-use
            assertTrue(c.authentication.authenticate("alice", assertionChallengeId, "cred-restore-1", 3,
                    TestKeys.sign(kp, TestKeys.assertionMessage(ORIGIN, "alice", assertionChallenge,
                            "cred-restore-1", 3)), ORIGIN));
            ApiException replay = assertThrows(ApiException.class, () ->
                    c.authentication.authenticate("alice", assertionChallengeId, "cred-restore-1", 4,
                            TestKeys.sign(kp, TestKeys.assertionMessage(ORIGIN, "alice",
                                    assertionChallenge, "cred-restore-1", 4)), ORIGIN));
            assertEquals(ErrorCode.CHALLENGE_NOT_FOUND, replay.getCode());

            // clone detection still enforced after restart using persisted state
            ApiException clone = assertThrows(ApiException.class, () -> {
                AssertionChallenge a5 = c.challenges.createAssertion("alice", ORIGIN);
                c.authentication.authenticate("alice", a5.getChallengeId(), "cred-restore-1", 1,
                        TestKeys.sign(kp, TestKeys.assertionMessage(ORIGIN, "alice", a5.getChallenge(),
                                "cred-restore-1", 1)), ORIGIN);
            });
            assertEquals(ErrorCode.COUNTER_CLONE_DETECTED, clone.getCode());
        }
    }
}
