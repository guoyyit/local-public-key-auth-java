package com.github.guoyyit.localpublickeyauthjava.tests;

import com.github.guoyyit.localpublickeyauthjava.config.AuthProperties;
import com.github.guoyyit.localpublickeyauthjava.model.ApiException;
import com.github.guoyyit.localpublickeyauthjava.model.AssertionChallenge;
import com.github.guoyyit.localpublickeyauthjava.model.Credential;
import com.github.guoyyit.localpublickeyauthjava.model.CredentialStatus;
import com.github.guoyyit.localpublickeyauthjava.model.ErrorCode;
import com.github.guoyyit.localpublickeyauthjava.model.RegistrationSession;
import com.github.guoyyit.localpublickeyauthjava.service.AuthenticationService;
import com.github.guoyyit.localpublickeyauthjava.service.ChallengeService;
import com.github.guoyyit.localpublickeyauthjava.service.CredentialService;
import com.github.guoyyit.localpublickeyauthjava.service.TimeProvider;
import com.github.guoyyit.localpublickeyauthjava.store.JsonFileStore;
import com.github.guoyyit.localpublickeyauthjava.tests.support.MutableTimeProvider;
import com.github.guoyyit.localpublickeyauthjava.tests.support.TestKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.TestPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
        "auth.expected-origin=https://app.example.com",
        "auth.registration-ttl-seconds=5",
        "auth.assertion-ttl-seconds=2",
        "auth.store-file=./target/test-data/auth-service.json"
})
class AuthServiceTests {

    @TestConfiguration
    static class ClockConfig {
        @Bean
        @Primary
        MutableTimeProvider mutableClock() {
            return new MutableTimeProvider();
        }
    }

    static final String ORIGIN = "https://app.example.com";

    @Autowired ChallengeService challenges;
    @Autowired CredentialService credentials;
    @Autowired AuthenticationService authentication;
    @Autowired TimeProvider clock;
    @Autowired AuthProperties properties;
    @Autowired JsonFileStore store;

    @BeforeEach
    void resetStore() {
        store.reset();
        ((MutableTimeProvider) clock).set(System.currentTimeMillis());
    }

    private String register(String user, String credId, KeyPair kp) {
        RegistrationSession session = challenges.createRegistration(user, ORIGIN);
        String pk = TestKeys.publicKey(kp);
        byte[] msg = TestKeys.registrationMessage(ORIGIN, user, session.getChallenge(), credId, pk);
        credentials.register(user, session.getSessionId(), ORIGIN, credId, pk, TestKeys.sign(kp, msg));
        return pk;
    }

    private AssertionChallenge start(String user) {
        return challenges.createAssertion(user, ORIGIN);
    }

    private void login(String user, AssertionChallenge ch, String credId, KeyPair kp, long counter) {
        byte[] msg = TestKeys.assertionMessage(ORIGIN, user, ch.getChallenge(), credId, counter);
        authentication.authenticate(user, ch.getChallengeId(), credId, counter,
                TestKeys.sign(kp, msg), ORIGIN);
    }

    @Test
    void registersCredentialAndLogsIn() {
        KeyPair kp = TestKeys.generate();
        register("alice", "cred-alice-1", kp);

        AssertionChallenge ch = start("alice");
        login("alice", ch, "cred-alice-1", kp, 0);

        Credential stored = credentials.findActive("alice", "cred-alice-1");
        assertEquals(0, stored.getCounter());

        AssertionChallenge ch2 = start("alice");
        login("alice", ch2, "cred-alice-1", kp, 1);
        assertEquals(1, credentials.findActive("alice", "cred-alice-1").getCounter());
    }

    @Test
    void rejectsBadSignature() {
        KeyPair kp = TestKeys.generate();
        register("alice", "cred-alice-badsig", kp);
        AssertionChallenge ch = start("alice");
        byte[] msg = TestKeys.assertionMessage(ORIGIN, "alice", ch.getChallenge(), "cred-alice-badsig", 0);

        ApiException ex = assertThrows(ApiException.class, () ->
                authentication.authenticate("alice", ch.getChallengeId(), "cred-alice-badsig", 0,
                        TestKeys.sign(TestKeys.generate(), msg), ORIGIN));
        assertEquals(ErrorCode.INVALID_SIGNATURE, ex.getCode());

        // challenge was consumed atomically even though signature failed
        ApiException again = assertThrows(ApiException.class, () ->
                authentication.authenticate("alice", ch.getChallengeId(), "cred-alice-badsig", 0,
                        TestKeys.sign(kp, msg), ORIGIN));
        assertEquals(ErrorCode.CHALLENGE_NOT_FOUND, again.getCode());
    }

    @Test
    void rejectsReplayedChallenge() {
        KeyPair kp = TestKeys.generate();
        register("alice", "cred-alice-replay", kp);
        AssertionChallenge ch = start("alice");
        login("alice", ch, "cred-alice-replay", kp, 0);

        byte[] msg = TestKeys.assertionMessage(ORIGIN, "alice", ch.getChallenge(),
                "cred-alice-replay", 1);
        ApiException ex = assertThrows(ApiException.class, () ->
                authentication.authenticate("alice", ch.getChallengeId(), "cred-alice-replay", 1,
                        TestKeys.sign(kp, msg), ORIGIN));
        assertEquals(ErrorCode.CHALLENGE_NOT_FOUND, ex.getCode());
    }

    @Test
    void rejectsExpiredChallenges() {
        KeyPair kp = TestKeys.generate();
        register("alice", "cred-alice-exp", kp);

        AssertionChallenge ch = start("alice");
        ((MutableTimeProvider) clock).advance(3000);
        byte[] msg = TestKeys.assertionMessage(ORIGIN, "alice", ch.getChallenge(), "cred-alice-exp", 0);
        ApiException ex = assertThrows(ApiException.class, () ->
                authentication.authenticate("alice", ch.getChallengeId(), "cred-alice-exp", 0,
                        TestKeys.sign(kp, msg), ORIGIN));
        assertEquals(ErrorCode.CHALLENGE_EXPIRED, ex.getCode());

        RegistrationSession session = challenges.createRegistration("alice", ORIGIN);
        ((MutableTimeProvider) clock).advance(6000);
        ApiException regEx = assertThrows(ApiException.class, () ->
                credentials.register("alice", session.getSessionId(), ORIGIN, "cred-alice-exp2",
                        TestKeys.publicKey(kp), "x"));
        assertEquals(ErrorCode.CHALLENGE_EXPIRED, regEx.getCode());
    }

    @Test
    void rejectsWrongOrigin() {
        KeyPair kp = TestKeys.generate();
        ApiException ex = assertThrows(ApiException.class, () ->
                challenges.createRegistration("alice", "https://evil.example.org"));
        assertEquals(ErrorCode.ORIGIN_MISMATCH, ex.getCode());

        register("alice", "cred-alice-origin", kp);
        AssertionChallenge ch = start("alice");
        byte[] msg = TestKeys.assertionMessage("https://evil.example.org", "alice",
                ch.getChallenge(), "cred-alice-origin", 0);
        ApiException verifyEx = assertThrows(ApiException.class, () ->
                authentication.authenticate("alice", ch.getChallengeId(), "cred-alice-origin", 0,
                        TestKeys.sign(kp, msg), "https://evil.example.org"));
        assertEquals(ErrorCode.ORIGIN_MISMATCH, verifyEx.getCode());
    }

    @Test
    void rejectsWrongUserBinding() {
        KeyPair kpA = TestKeys.generate();
        register("alice", "cred-bound-a", kpA);

        // challenge minted for alice cannot be used pretending to be bob
        AssertionChallenge ch = start("alice");
        byte[] msg = TestKeys.assertionMessage(ORIGIN, "bob", ch.getChallenge(), "cred-bound-a", 0);
        ApiException ex = assertThrows(ApiException.class, () ->
                authentication.authenticate("bob", ch.getChallengeId(), "cred-bound-a", 0,
                        TestKeys.sign(kpA, msg), ORIGIN));
        assertEquals(ErrorCode.CHALLENGE_USER_MISMATCH, ex.getCode());

        // bob cannot use alice's credential
        AssertionChallenge bobCh = start("bob");
        byte[] msg2 = TestKeys.assertionMessage(ORIGIN, "bob", bobCh.getChallenge(), "cred-bound-a", 0);
        ApiException ex2 = assertThrows(ApiException.class, () ->
                authentication.authenticate("bob", bobCh.getChallengeId(), "cred-bound-a", 0,
                        TestKeys.sign(kpA, msg2), ORIGIN));
        assertEquals(ErrorCode.CREDENTIAL_NOT_FOUND, ex2.getCode());
    }

    @Test
    void multipleCredentialsPerUserAndIndependentLifecycle() {
        KeyPair kp1 = TestKeys.generate();
        KeyPair kp2 = TestKeys.generate();
        register("alice", "cred-multi-1", kp1);
        register("alice", "cred-multi-2", kp2);
        assertEquals(2, credentials.list("alice").size());

        login("alice", start("alice"), "cred-multi-1", kp1, 0);
        credentials.disable("alice", "cred-multi-1");

        ApiException disabled = assertThrows(ApiException.class, () ->
                login("alice", start("alice"), "cred-multi-1", kp1, 1));
        assertEquals(ErrorCode.CREDENTIAL_REVOKED, disabled.getCode());

        // second credential still works
        login("alice", start("alice"), "cred-multi-2", kp2, 0);

        credentials.revoke("alice", "cred-multi-2");
        ApiException revoked = assertThrows(ApiException.class, () ->
                login("alice", start("alice"), "cred-multi-2", kp2, 1));
        assertEquals(ErrorCode.CREDENTIAL_REVOKED, revoked.getCode());
    }

    @Test
    void detectsCounterCloneAndRollback() {
        KeyPair kp = TestKeys.generate();
        register("alice", "cred-clone", kp);
        login("alice", start("alice"), "cred-clone", kp, 1);
        login("alice", start("alice"), "cred-clone", kp, 2);

        // replay of old counter (cloned authenticator)
        ApiException clone = assertThrows(ApiException.class, () ->
                login("alice", start("alice"), "cred-clone", kp, 1));
        assertEquals(ErrorCode.COUNTER_CLONE_DETECTED, clone.getCode());

        // credential is revoked automatically
        assertEquals(CredentialStatus.REVOKED, credentials.list("alice").stream()
                .filter(c -> c.getCredentialId().equals("cred-clone")).findFirst().orElseThrow().getStatus());
    }

    @Test
    void concurrentAssertionsDoNotFalsePositive() throws Exception {
        KeyPair kp = TestKeys.generate();
        register("alice", "cred-conc", kp);

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Boolean>> futures = new ArrayList<>();

        for (int i = 1; i <= threads; i++) {
            long counter = i;
            futures.add(pool.submit((Callable<Boolean>) () -> {
                AssertionChallenge ch = challenges.createAssertion("alice", ORIGIN);
                ready.countDown();
                go.await();
                byte[] msg = TestKeys.assertionMessage(ORIGIN, "alice", ch.getChallenge(),
                        "cred-conc", counter);
                authentication.authenticate("alice", ch.getChallengeId(), "cred-conc", counter,
                        TestKeys.sign(kp, msg), ORIGIN);
                return true;
            }));
        }
        ready.await();
        go.countDown();
        for (Future<Boolean> f : futures) {
            assertTrue(f.get(10, TimeUnit.SECONDS));
        }
        pool.shutdown();
        assertEquals(threads, credentials.findActive("alice", "cred-conc").getCounter());
    }

    @Test
    void concurrentRegistrationsAreIndependent() {
        KeyPair kp = TestKeys.generate();
        RegistrationSession s1 = challenges.createRegistration("alice", ORIGIN);
        RegistrationSession s2 = challenges.createRegistration("alice", ORIGIN);
        assertNotEquals(s1.getSessionId(), s2.getSessionId());
        assertNotEquals(s1.getChallenge(), s2.getChallenge());

        String pk = TestKeys.publicKey(kp);
        byte[] m1 = TestKeys.registrationMessage(ORIGIN, "alice", s1.getChallenge(), "cred-conc-r1", pk);
        credentials.register("alice", s1.getSessionId(), ORIGIN, "cred-conc-r1", pk, TestKeys.sign(kp, m1));

        // s2 untouched and still consumable
        byte[] m2 = TestKeys.registrationMessage(ORIGIN, "alice", s2.getChallenge(), "cred-conc-r2", pk);
        credentials.register("alice", s2.getSessionId(), ORIGIN, "cred-conc-r2", pk, TestKeys.sign(kp, m2));

        // session cannot be completed twice
        byte[] m1b = TestKeys.registrationMessage(ORIGIN, "alice", s1.getChallenge(), "cred-conc-r3", pk);
        ApiException ex = assertThrows(ApiException.class, () ->
                credentials.register("alice", s1.getSessionId(), ORIGIN, "cred-conc-r3", pk,
                        TestKeys.sign(kp, m1b)));
        assertEquals(ErrorCode.CHALLENGE_NOT_FOUND, ex.getCode());
    }

    @Test
    void rejectsDuplicateCredentialIdAcrossUsers() {
        KeyPair kp1 = TestKeys.generate();
        register("alice", "shared-cred-id", kp1);

        KeyPair kp2 = TestKeys.generate();
        RegistrationSession session = challenges.createRegistration("bob", ORIGIN);
        String pk = TestKeys.publicKey(kp2);
        byte[] msg = TestKeys.registrationMessage(ORIGIN, "bob", session.getChallenge(), "shared-cred-id", pk);
        ApiException ex = assertThrows(ApiException.class, () ->
                credentials.register("bob", session.getSessionId(), ORIGIN, "shared-cred-id", pk,
                        TestKeys.sign(kp2, msg)));
        assertEquals(ErrorCode.CREDENTIAL_ALREADY_EXISTS, ex.getCode());
    }

    @Test
    void cleanupPurgesExpired() {
        challenges.createRegistration("alice", ORIGIN);
        start("alice");
        ((MutableTimeProvider) clock).advance(10_000);
        int removed = challenges.purgeExpired();
        assertTrue(removed >= 2);
    }

    @Test
    void outOfOrderArrivalKeepsReplayDetectionWithinWindow() {
        KeyPair kp = TestKeys.generate();
        register("alice", "cred-ooo", kp);

        // 10 then 1 (out of order): both accepted, high-water 10
        login("alice", start("alice"), "cred-ooo", kp, 10);
        login("alice", start("alice"), "cred-ooo", kp, 1);

        // replaying the older out-of-order value is still detected
        ApiException replay = assertThrows(ApiException.class, () ->
                login("alice", start("alice"), "cred-ooo", kp, 1));
        assertEquals(ErrorCode.COUNTER_CLONE_DETECTED, replay.getCode());
        assertEquals(CredentialStatus.REVOKED,
                credentials.list("alice").stream()
                        .filter(c -> c.getCredentialId().equals("cred-ooo"))
                        .findFirst().orElseThrow().getStatus());
    }

    @Test
    void stateIsDurablyWrittenToStoreFile() throws Exception {
        KeyPair kp = TestKeys.generate();
        register("alice", "cred-durable", kp);
        login("alice", start("alice"), "cred-durable", kp, 1);

        Path storePath = Path.of(properties.getStoreFile());
        assertTrue(Files.exists(storePath));
        String json = Files.readString(storePath);
        // the flushed JSON contains the credential, the persisted counter and
        // no trace of the (already consumed) sessions/challenges
        assertTrue(json.contains("cred-durable"));
        assertTrue(json.contains("\"counter\" : 1"));
        assertTrue(!json.contains("assertions") || json.contains("\"assertions\" : { }"));
    }
}
