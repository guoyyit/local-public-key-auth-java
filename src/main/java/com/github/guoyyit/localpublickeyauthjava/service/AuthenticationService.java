package com.github.guoyyit.localpublickeyauthjava.service;

import com.github.guoyyit.localpublickeyauthjava.config.AuthProperties;
import com.github.guoyyit.localpublickeyauthjava.crypto.SignatureVerifier;
import com.github.guoyyit.localpublickeyauthjava.model.ApiException;
import com.github.guoyyit.localpublickeyauthjava.model.AssertionChallenge;
import com.github.guoyyit.localpublickeyauthjava.model.Credential;
import com.github.guoyyit.localpublickeyauthjava.model.CredentialStatus;
import com.github.guoyyit.localpublickeyauthjava.model.ErrorCode;
import com.github.guoyyit.localpublickeyauthjava.store.JsonFileStore;
import com.github.guoyyit.localpublickeyauthjava.util.MessageBuilder;
import org.springframework.stereotype.Service;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Verifies login assertions.
 *
 * <p>A single atomic store transaction performs challenge lookup/consumption,
 * credential ownership and status checks, signature verification and the
 * monotonic counter update, so concurrent assertions are serialized per store
 * and the counter is committed atomically with challenge consumption.
 *
 * <h2>Counter policy</h2>
 * A credential carries a high-water mark ({@code counter}) plus the set of
 * recently accepted counter values ({@code recentCounters}).
 * <ul>
 *   <li>a value already seen &rarr; replay/clone &rarr; credential revoked;</li>
 *   <li>a value older than {@code highWater - window} &rarr; rollback beyond
 *       what concurrent reordering can explain &rarr; credential revoked;</li>
 *   <li>strictly increasing values advance the high-water mark;</li>
 *   <li>unseen values inside the tolerance span are accepted as out-of-order
 *       concurrent assertions, so concurrency never falsely rejects honest
 *       assertions, while any later reuse is still caught.</li>
 * </ul>
 */
@Service
public class AuthenticationService {

    private static final Pattern CREDENTIAL_ID = Pattern.compile("[A-Za-z0-9_-]{8,128}");
    private static final Pattern USER_ID = Pattern.compile("[A-Za-z0-9_.@-]{1,128}");

    private final JsonFileStore store;
    private final SignatureVerifier verifier;
    private final AuthProperties properties;
    private final TimeProvider time;
    private final ChallengeService challenges;

    public AuthenticationService(JsonFileStore store, SignatureVerifier verifier,
                                 AuthProperties properties, TimeProvider time,
                                 ChallengeService challenges) {
        this.store = store;
        this.verifier = verifier;
        this.properties = properties;
        this.time = time;
        this.challenges = challenges;
    }

    /**
     * @return true when the assertion is valid; throws {@link ApiException}
     *         describing the failure otherwise (in particular a successful
     *         cryptographic check with a reused/rolled-back counter revokes
     *         the credential and throws COUNTER_CLONE_DETECTED)
     */
    public boolean authenticate(String userId, String challengeId, String credentialId,
                                long counter, String signature, String origin) {
        requireText(userId, "userId");
        requireText(challengeId, "challengeId");
        requireText(credentialId, "credentialId");
        requireText(signature, "signature");
        requireText(origin, "origin");
        if (!USER_ID.matcher(userId).matches()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "invalid userId format");
        }
        if (!CREDENTIAL_ID.matcher(credentialId).matches()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "invalid credentialId format");
        }
        if (counter < 0) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "counter must be non-negative");
        }

        long now = time.nowMillis();
        store.mutate(data -> {
            AssertionChallenge challenge = challenges.takeAssertion(data, challengeId, userId, origin);

            Credential credential = data.getCredentials().get(credentialId);
            if (credential == null || !credential.getUserId().equals(userId)) {
                throw new ApiException(ErrorCode.CREDENTIAL_NOT_FOUND, "credential not found");
            }
            if (credential.getStatus() != CredentialStatus.ACTIVE) {
                throw new ApiException(ErrorCode.CREDENTIAL_REVOKED,
                        "credential is " + credential.getStatus().name().toLowerCase());
            }

            byte[] message = MessageBuilder.assertionMessage(
                    origin, userId, challenge.getChallenge(), credentialId, counter);
            if (!verifier.verify(credential.getPublicKey(), message, signature)) {
                throw new ApiException(ErrorCode.INVALID_SIGNATURE, "assertion signature does not verify");
            }

            checkAndAdvanceCounter(credential, counter, now);
            return null;
        });
        return true;
    }

    private void checkAndAdvanceCounter(Credential credential, long counter, long now) {
        long highWater = credential.getCounter();
        Set<Long> recent = credential.getRecentCounters();
        if (recent == null) {
            recent = new LinkedHashSet<>();
            credential.setRecentCounters(recent);
        }

        // A fresh credential starts at counter 0; an authenticator's first
        // assertion may legitimately carry 0 exactly once.
        if (highWater == 0 && recent.isEmpty() && counter == 0) {
            remember(recent, counter, counter);
            credential.setUpdatedAt(now);
            return;
        }

        long newHigh = Math.max(highWater, counter);
        if (recent.contains(counter)) {
            // exact value already used: replay or cloned authenticator
            credential.setStatus(CredentialStatus.REVOKED);
            credential.setUpdatedAt(now);
            throw new ApiException(ErrorCode.COUNTER_CLONE_DETECTED,
                    "counter reuse/rollback detected; credential revoked");
        }
        if (counter <= highWater - properties.getRecentCountersWindow()) {
            // older than the in-flight tolerance span can explain: rollback
            credential.setStatus(CredentialStatus.REVOKED);
            credential.setUpdatedAt(now);
            throw new ApiException(ErrorCode.COUNTER_CLONE_DETECTED,
                    "counter rollback beyond tolerated window; credential revoked");
        }

        // new value, either a strict advance or a legitimately out-of-order
        // concurrent assertion inside the tolerance span
        credential.setCounter(newHigh);
        remember(recent, counter, newHigh);
        credential.setUpdatedAt(now);
    }

    private void remember(Set<Long> recent, long counter, long highWater) {
        recent.add(counter);
        long floor = highWater - properties.getRecentCountersWindow();
        // forget exactly the values that have aged out of the tolerance span;
        // membership of every still-relevant value is preserved regardless of
        // the arrival order of concurrent assertions
        recent.removeIf(v -> v <= floor);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, field + " is required");
        }
    }
}
