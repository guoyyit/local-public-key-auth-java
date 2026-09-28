package com.github.guoyyit.localpublickeyauthjava.service;

import com.github.guoyyit.localpublickeyauthjava.config.AuthProperties;
import com.github.guoyyit.localpublickeyauthjava.model.ApiException;
import com.github.guoyyit.localpublickeyauthjava.model.AssertionChallenge;
import com.github.guoyyit.localpublickeyauthjava.model.ErrorCode;
import com.github.guoyyit.localpublickeyauthjava.model.Expirable;
import com.github.guoyyit.localpublickeyauthjava.model.RegistrationSession;
import com.github.guoyyit.localpublickeyauthjava.store.JsonFileStore;
import com.github.guoyyit.localpublickeyauthjava.store.StoreData;
import com.github.guoyyit.localpublickeyauthjava.util.CryptoRandom;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Issues and consumes registration sessions and login challenges.
 *
 * <p>Every challenge is a 256-bit random value bound to a specific user,
 * origin and point in time. Each user can have multiple concurrent sessions:
 * they are keyed by independent random ids, so creating a new one never
 * overwrites another in progress. Challenges are single-use: consumption
 * removes them, so they cannot be replayed. Expired entries are purged on
 * access and by the scheduled cleanup.
 */
@Service
public class ChallengeService {

    private final JsonFileStore store;
    private final AuthProperties properties;
    private final TimeProvider time;

    public ChallengeService(JsonFileStore store, AuthProperties properties, TimeProvider time) {
        this.store = store;
        this.properties = properties;
        this.time = time;
    }

    public RegistrationSession createRegistration(String userId, String origin) {
        requireOrigin(origin);
        long now = time.nowMillis();
        RegistrationSession session = new RegistrationSession(
                CryptoRandom.randomId(), userId, CryptoRandom.randomChallenge(), origin,
                now, now + properties.getRegistrationTtlSeconds() * 1000);
        return store.mutate(data -> {
            data.getRegistrations().put(session.getSessionId(), session);
            return session;
        });
    }

    public AssertionChallenge createAssertion(String userId, String origin) {
        requireOrigin(origin);
        long now = time.nowMillis();
        AssertionChallenge challenge = new AssertionChallenge(
                CryptoRandom.randomId(), userId, CryptoRandom.randomChallenge(), origin,
                now, now + properties.getAssertionTtlSeconds() * 1000);
        return store.mutate(data -> {
            data.getAssertions().put(challenge.getChallengeId(), challenge);
            return challenge;
        });
    }

    /**
     * Validate and consume a registration session inside an existing mutation.
     * The session is removed (single use) on success.
     */
    public RegistrationSession takeRegistration(StoreData data, String sessionId,
                                                String userId, String origin) {
        RegistrationSession session = data.getRegistrations().get(sessionId);
        if (session == null) {
            throw new ApiException(ErrorCode.CHALLENGE_NOT_FOUND, "registration session not found");
        }
        if (!session.getUserId().equals(userId)) {
            throw new ApiException(ErrorCode.CHALLENGE_USER_MISMATCH,
                    "registration session is bound to another user");
        }
        if (session.isConsumed()) {
            throw new ApiException(ErrorCode.CHALLENGE_CONSUMED, "registration session already used");
        }
        if (time.nowMillis() > session.getExpiresAt()) {
            data.getRegistrations().remove(sessionId);
            throw new ApiException(ErrorCode.CHALLENGE_EXPIRED, "registration session expired");
        }
        if (!session.getOrigin().equals(origin)) {
            throw new ApiException(ErrorCode.ORIGIN_MISMATCH, "origin does not match registration session");
        }
        data.getRegistrations().remove(sessionId);
        session.setConsumed(true);
        return session;
    }

    /**
     * Validate and consume an assertion challenge inside an existing mutation.
     * The challenge is removed (single use) on success.
     */
    public AssertionChallenge takeAssertion(StoreData data, String challengeId,
                                            String userId, String origin) {
        AssertionChallenge challenge = data.getAssertions().get(challengeId);
        if (challenge == null) {
            throw new ApiException(ErrorCode.CHALLENGE_NOT_FOUND, "assertion challenge not found");
        }
        if (!challenge.getUserId().equals(userId)) {
            throw new ApiException(ErrorCode.CHALLENGE_USER_MISMATCH,
                    "assertion challenge is bound to another user");
        }
        if (challenge.isConsumed()) {
            throw new ApiException(ErrorCode.CHALLENGE_CONSUMED, "assertion challenge already used");
        }
        if (time.nowMillis() > challenge.getExpiresAt()) {
            data.getAssertions().remove(challengeId);
            throw new ApiException(ErrorCode.CHALLENGE_EXPIRED, "assertion challenge expired");
        }
        if (!challenge.getOrigin().equals(origin)) {
            throw new ApiException(ErrorCode.ORIGIN_MISMATCH, "origin does not match assertion challenge");
        }
        data.getAssertions().remove(challengeId);
        challenge.setConsumed(true);
        return challenge;
    }

    private void requireOrigin(String origin) {
        if (origin == null || origin.isBlank()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "origin is required");
        }
        if (!origin.equals(properties.getExpectedOrigin())) {
            throw new ApiException(ErrorCode.ORIGIN_MISMATCH,
                    "origin is not a trusted origin for this server");
        }
    }

    /**
     * Remove all expired sessions and challenges. Returns the number removed.
     */
    public int purgeExpired() {
        long now = time.nowMillis();
        return store.mutate(data -> purge(data.getRegistrations(), now) + purge(data.getAssertions(), now));
    }

    private <T extends Expirable> int purge(Map<String, T> entries, long now) {
        int count = 0;
        var it = entries.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().getExpiresAt() < now) {
                it.remove();
                count++;
            }
        }
        return count;
    }
}
