package com.github.guoyyit.localpublickeyauthjava.service;

import com.github.guoyyit.localpublickeyauthjava.config.AuthProperties;
import com.github.guoyyit.localpublickeyauthjava.crypto.CryptoService;
import com.github.guoyyit.localpublickeyauthjava.domain.AuthChallenge;
import com.github.guoyyit.localpublickeyauthjava.domain.Credential;
import com.github.guoyyit.localpublickeyauthjava.domain.RegistrationSession;
import com.github.guoyyit.localpublickeyauthjava.error.AuthException;
import com.github.guoyyit.localpublickeyauthjava.error.ErrorCode;
import com.github.guoyyit.localpublickeyauthjava.store.AuthStore;
import com.github.guoyyit.localpublickeyauthjava.web.dto.CredentialView;
import com.github.guoyyit.localpublickeyauthjava.web.dto.LoginAssertionRequest;
import com.github.guoyyit.localpublickeyauthjava.web.dto.LoginAssertionResponse;
import com.github.guoyyit.localpublickeyauthjava.web.dto.LoginStartRequest;
import com.github.guoyyit.localpublickeyauthjava.web.dto.LoginStartResponse;
import com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationCompleteRequest;
import com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationCompleteResponse;
import com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationStartRequest;
import com.github.guoyyit.localpublickeyauthjava.web.dto.RegistrationStartResponse;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;

/**
 * Registration, assertion and credential lifecycle logic.
 *
 * <p>All state transitions happen inside a single serialized {@link AuthStore#mutate} call and
 * are persisted before the call returns, so validation and persistence form one atomic step.
 */
@Service
public class AuthService {

    private static final Set<String> SUPPORTED_ALGORITHMS =
            Set.of(CryptoService.ALG_ED25519, CryptoService.ALG_EC_P256);
    private static final long GAP_RETRY_SLEEP_MS = 5;

    private final AuthStore store;
    private final CryptoService crypto;
    private final AuthProperties properties;

    public AuthService(AuthStore store, CryptoService crypto, AuthProperties properties) {
        this.store = store;
        this.crypto = crypto;
        this.properties = properties;
    }

    // ---------------- registration ----------------

    public RegistrationStartResponse startRegistration(RegistrationStartRequest req) {
        String userId = requireUser(req == null ? null : req.userId());
        String origin = requireOrigin(req == null ? null : req.origin());
        long now = System.currentTimeMillis();
        RegistrationSession session = new RegistrationSession(
                crypto.newId(),
                userId,
                origin,
                crypto.newChallenge(),
                now,
                now + properties.getRegistrationTtlSeconds() * 1000L,
                false);
        store.mutate(v -> v.sessions().add(session));
        return new RegistrationStartResponse(
                session.sessionId(), session.userId(), session.challenge(), session.expiresAt());
    }

    public RegistrationCompleteResponse completeRegistration(RegistrationCompleteRequest req) {
        if (req == null) {
            throw new AuthException(ErrorCode.INVALID_REQUEST, "request body is required");
        }
        String userId = requireUser(req.userId());
        String origin = requireOrigin(req.origin());
        requireText(req.sessionId(), "sessionId", ErrorCode.INVALID_REQUEST);
        requireText(req.credentialId(), "credentialId", ErrorCode.MALFORMED_CREDENTIAL);
        requireText(req.publicKey(), "publicKey", ErrorCode.MALFORMED_CREDENTIAL);
        requireText(req.signature(), "signature", ErrorCode.MALFORMED_CREDENTIAL);
        if (req.algorithm() == null || !SUPPORTED_ALGORITHMS.contains(req.algorithm())) {
            throw new AuthException(ErrorCode.UNSUPPORTED_ALGORITHM,
                    "algorithm must be one of " + SUPPORTED_ALGORITHMS);
        }
        // Parse and curve-check the key before any state transition.
        PublicKey publicKey = crypto.parsePublicKey(req.algorithm(), req.publicKey());
        verifyKeyCurve(req.algorithm(), publicKey);

        store.mutate(v -> {
            RegistrationSession session = v.sessions().stream()
                    .filter(s -> s.sessionId().equals(req.sessionId()))
                    .findFirst()
                    .orElseThrow(() -> new AuthException(ErrorCode.SESSION_NOT_FOUND,
                            "registration session not found or already used"));
            long now = System.currentTimeMillis();
            if (session.expiresAt() <= now) {
                throw new AuthException(ErrorCode.SESSION_EXPIRED, "registration session has expired");
            }
            if (session.consumed()) {
                throw new AuthException(ErrorCode.SESSION_ALREADY_USED, "registration session already used");
            }
            if (!session.userId().equals(userId)) {
                throw new AuthException(ErrorCode.USER_MISMATCH,
                        "session is bound to a different user");
            }
            if (!session.origin().equals(origin)) {
                throw new AuthException(ErrorCode.INVALID_ORIGIN,
                        "session is bound to a different origin");
            }
            boolean credentialExists = v.credentials().stream()
                    .anyMatch(c -> c.credentialId().equals(req.credentialId()));
            if (credentialExists) {
                throw new AuthException(ErrorCode.CREDENTIAL_EXISTS,
                        "credential id is already registered");
            }
            byte[] signedData = crypto.registrationSignedData(
                    userId, origin, session.challenge(), req.credentialId());
            if (!crypto.verifySignature(publicKey, req.algorithm(),
                    signedData, crypto.decodeUrlBase64(req.signature()))) {
                throw new AuthException(ErrorCode.SIGNATURE_INVALID,
                        "registration signature does not verify against the supplied public key");
            }
            long ts = System.currentTimeMillis();
            v.credentials().add(new Credential(
                    req.credentialId(),
                    userId,
                    req.algorithm(),
                    req.publicKey(),
                    0L,
                    true,
                    ts,
                    0L));
            // Single use: mark the session consumed together with the credential insert, atomically.
            v.sessions().set(v.sessions().indexOf(session),
                    new RegistrationSession(session.sessionId(), session.userId(), session.origin(),
                            session.challenge(), session.createdAt(), session.expiresAt(), true));
        });
        return new RegistrationCompleteResponse(req.credentialId(), userId, "registered");
    }

    // ---------------- login / assertion ----------------

    public LoginStartResponse startLogin(LoginStartRequest req) {
        String userId = requireUser(req == null ? null : req.userId());
        String origin = requireOrigin(req == null ? null : req.origin());
        long now = System.currentTimeMillis();
        AuthChallenge challenge = new AuthChallenge(
                crypto.newId(),
                userId,
                origin,
                crypto.newChallenge(),
                now,
                now + properties.getChallengeTtlSeconds() * 1000L,
                false);
        store.mutate(v -> v.challenges().add(challenge));
        return new LoginStartResponse(
                challenge.challengeId(), challenge.userId(), challenge.challenge(), challenge.expiresAt());
    }

    public LoginAssertionResponse verifyAssertion(LoginAssertionRequest req) {
        if (req == null) {
            throw new AuthException(ErrorCode.INVALID_REQUEST, "request body is required");
        }
        String userId = requireUser(req.userId());
        String origin = requireOrigin(req.origin());
        requireText(req.challengeId(), "challengeId", ErrorCode.INVALID_REQUEST);
        requireText(req.credentialId(), "credentialId", ErrorCode.INVALID_REQUEST);
        requireText(req.signature(), "signature", ErrorCode.INVALID_REQUEST);
        if (req.signCount() < 0) {
            throw new AuthException(ErrorCode.INVALID_REQUEST, "signCount must be non-negative");
        }

        // Phase 1: validate against a consistent snapshot and verify the signature.
        record Snapshot(AuthChallenge challenge, Credential credential) {
        }
        Snapshot snapshot = store.read(v -> {
            AuthChallenge challenge = v.challenges().stream()
                    .filter(c -> c.challengeId().equals(req.challengeId()))
                    .findFirst()
                    .orElseThrow(() -> new AuthException(ErrorCode.CHALLENGE_NOT_FOUND,
                            "challenge not found or already reclaimed"));
            if (challenge.consumed()) {
                throw new AuthException(ErrorCode.CHALLENGE_REPLAY, "challenge has already been consumed");
            }
            if (challenge.expiresAt() <= System.currentTimeMillis()) {
                throw new AuthException(ErrorCode.CHALLENGE_EXPIRED, "challenge has expired");
            }
            if (!challenge.userId().equals(userId)) {
                throw new AuthException(ErrorCode.USER_MISMATCH, "challenge is bound to a different user");
            }
            if (!challenge.origin().equals(origin)) {
                throw new AuthException(ErrorCode.INVALID_ORIGIN, "challenge is bound to a different origin");
            }
            Credential credential = v.credentials().stream()
                    .filter(c -> c.credentialId().equals(req.credentialId())
                            && c.userId().equals(userId))
                    .findFirst()
                    .orElseThrow(() -> new AuthException(ErrorCode.UNKNOWN_CREDENTIAL,
                            "credential is not registered for this user"));
            if (!credential.enabled()) {
                throw new AuthException(ErrorCode.CREDENTIAL_DISABLED, "credential has been disabled");
            }
            return new Snapshot(challenge, credential);
        });

        byte[] signedData = crypto.assertionSignedData(
                userId, origin, snapshot.challenge().challenge(),
                req.credentialId(), req.signCount());
        PublicKey publicKey = crypto.parsePublicKey(snapshot.credential().algorithm(),
                snapshot.credential().publicKeyBase64());
        byte[] signature = crypto.decodeUrlBase64(req.signature());
        if (!crypto.verifySignature(publicKey, snapshot.credential().algorithm(), signedData, signature)) {
            // A forged signature does not consume the challenge; the client may retry.
            throw new AuthException(ErrorCode.SIGNATURE_INVALID, "assertion signature verification failed");
        }

        // Phase 2: atomic compare-and-commit of the counter. A strictly larger counter is
        // required. When concurrent assertions for the same credential arrive out of order,
        // wait briefly for the missing intermediate counters to land instead of flagging a
        // clone. The wait happens outside the store lock so other assertions can still commit.
        long deadline = System.currentTimeMillis() + properties.getCounterGapTimeoutMs();
        CommitOutcome outcome;
        while (true) {
            OutcomeHolder holder = new OutcomeHolder();
            store.mutate(v -> {
                AuthChallenge challenge = v.challenges().stream()
                        .filter(c -> c.challengeId().equals(req.challengeId()))
                        .findFirst()
                        .orElse(null);
                if (challenge == null || challenge.consumed()) {
                    // It existed after a valid signature a moment ago and is now consumed: replay.
                    holder.outcome = CommitOutcome.REPLAY;
                    return;
                }
                if (challenge.expiresAt() <= System.currentTimeMillis()) {
                    holder.outcome = CommitOutcome.EXPIRED;
                    return;
                }
                Credential credential = null;
                int credIndex = -1;
                for (int i = 0; i < v.credentials().size(); i++) {
                    Credential c = v.credentials().get(i);
                    if (c.credentialId().equals(req.credentialId()) && c.userId().equals(userId)) {
                        credential = c;
                        credIndex = i;
                        break;
                    }
                }
                if (credential == null) {
                    holder.outcome = CommitOutcome.UNKNOWN;
                    return;
                }
                if (!credential.enabled()) {
                    holder.outcome = CommitOutcome.DISABLED;
                    return;
                }
                long current = credential.signCount();
                if (req.signCount() <= current) {
                    // Valid signature over a non-increasing counter: cloned or rewound credential.
                    markChallengeConsumed(v, challenge);
                    holder.outcome = CommitOutcome.CLONE;
                    return;
                }
                if (req.signCount() > current + 1) {
                    holder.outcome = CommitOutcome.GAP;
                    return;
                }
                v.credentials().set(credIndex, new Credential(
                        credential.credentialId(),
                        credential.userId(),
                        credential.algorithm(),
                        credential.publicKeyBase64(),
                        req.signCount(),
                        credential.enabled(),
                        credential.registeredAt(),
                        System.currentTimeMillis()));
                markChallengeConsumed(v, challenge);
                holder.outcome = CommitOutcome.COMMITTED;
            });
            outcome = holder.outcome;

            switch (outcome) {
                case COMMITTED -> {
                    return new LoginAssertionResponse(userId, req.credentialId(), req.signCount(), "authenticated");
                }
                case CLONE -> throw new AuthException(ErrorCode.CLONE_DETECTED,
                        "signCount did not strictly increase; credential may have been cloned");
                case REPLAY -> throw new AuthException(ErrorCode.CHALLENGE_REPLAY,
                        "challenge has already been consumed");
                case EXPIRED -> throw new AuthException(ErrorCode.CHALLENGE_EXPIRED, "challenge has expired");
                case UNKNOWN -> throw new AuthException(ErrorCode.UNKNOWN_CREDENTIAL,
                        "credential is not registered for this user");
                case DISABLED -> throw new AuthException(ErrorCode.CREDENTIAL_DISABLED,
                        "credential has been disabled");
                case GAP -> {
                    if (System.currentTimeMillis() < deadline) {
                        try {
                            Thread.sleep(GAP_RETRY_SLEEP_MS);
                        } catch (InterruptedException ex) {
                            Thread.currentThread().interrupt();
                            throw new AuthException(ErrorCode.CONCURRENCY_CONFLICT,
                                    "interrupted while waiting for ordered counters", ex);
                        }
                    } else {
                        // Timed out waiting for intermediate counters. The signature is valid and
                        // the counter still strictly increases, so accept the jump rather than
                        // misjudging an authenticator that advances its counter by more than one.
                        store.mutate(v -> forceCommit(v, req, userId));
                        return new LoginAssertionResponse(userId, req.credentialId(), req.signCount(), "authenticated");
                    }
                }
            }
        }
    }

    private void forceCommit(AuthStore.StoreView v, LoginAssertionRequest req, String userId) {
        AuthChallenge challenge = v.challenges().stream()
                .filter(c -> c.challengeId().equals(req.challengeId()))
                .findFirst()
                .orElseThrow(() -> new AuthException(ErrorCode.CHALLENGE_REPLAY,
                        "challenge has already been consumed"));
        if (challenge.consumed()) {
            throw new AuthException(ErrorCode.CHALLENGE_REPLAY, "challenge has already been consumed");
        }
        if (challenge.expiresAt() <= System.currentTimeMillis()) {
            throw new AuthException(ErrorCode.CHALLENGE_EXPIRED, "challenge has expired");
        }
        for (int i = 0; i < v.credentials().size(); i++) {
            Credential c = v.credentials().get(i);
            if (c.credentialId().equals(req.credentialId()) && c.userId().equals(userId)) {
                if (req.signCount() <= c.signCount()) {
                    markChallengeConsumed(v, challenge);
                    throw new AuthException(ErrorCode.CLONE_DETECTED,
                            "signCount did not strictly increase; credential may have been cloned");
                }
                v.credentials().set(i, new Credential(
                        c.credentialId(), c.userId(), c.algorithm(), c.publicKeyBase64(),
                        req.signCount(), c.enabled(), c.registeredAt(), System.currentTimeMillis()));
                markChallengeConsumed(v, challenge);
                return;
            }
        }
        throw new AuthException(ErrorCode.UNKNOWN_CREDENTIAL, "credential is not registered for this user");
    }

    private void markChallengeConsumed(AuthStore.StoreView v, AuthChallenge challenge) {
        int index = v.challenges().indexOf(challenge);
        if (index >= 0) {
            v.challenges().set(index, new AuthChallenge(
                    challenge.challengeId(), challenge.userId(), challenge.origin(), challenge.challenge(),
                    challenge.createdAt(), challenge.expiresAt(), true));
        }
    }

    // ---------------- credential lifecycle ----------------

    public List<CredentialView> listCredentials(String userId) {
        String uid = requireUser(userId);
        return store.read(v -> v.credentials().stream()
                .filter(c -> c.userId().equals(uid))
                .map(c -> new CredentialView(c.credentialId(), c.userId(), c.algorithm(),
                        c.signCount(), c.enabled(), c.registeredAt(), c.lastUsedAt()))
                .toList());
    }

    public void disableCredential(String userId, String credentialId) {
        String uid = requireUser(userId);
        requireText(credentialId, "credentialId", ErrorCode.INVALID_REQUEST);
        store.mutate(v -> {
            for (int i = 0; i < v.credentials().size(); i++) {
                Credential c = v.credentials().get(i);
                if (c.credentialId().equals(credentialId) && c.userId().equals(uid)) {
                    v.credentials().set(i, new Credential(
                            c.credentialId(), c.userId(), c.algorithm(), c.publicKeyBase64(),
                            c.signCount(), false, c.registeredAt(), c.lastUsedAt()));
                    return;
                }
            }
            throw new AuthException(ErrorCode.UNKNOWN_CREDENTIAL,
                    "credential is not registered for this user");
        });
    }

    /**
     * Reclaims expired registration sessions and login challenges. Consumed records are kept
     * until expiry so replays can still be distinguished from unknown ids in that window.
     */
    public void purgeExpired() {
        long now = System.currentTimeMillis();
        store.mutate(v -> {
            v.sessions().removeIf(s -> s.expiresAt() <= now);
            v.challenges().removeIf(c -> c.expiresAt() <= now);
        });
    }

    // ---------------- helpers ----------------

    private void verifyKeyCurve(String algorithm, PublicKey publicKey) {
        if (CryptoService.ALG_EC_P256.equals(algorithm) && publicKey instanceof ECPublicKey ecKey) {
            int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
            if (fieldSize != 256) {
                throw new AuthException(ErrorCode.MALFORMED_CREDENTIAL,
                        "only P-256 EC keys are supported, got field size " + fieldSize);
            }
        }
    }

    private String requireUser(String userId) {
        if (userId == null || userId.isBlank()) {
            throw new AuthException(ErrorCode.INVALID_REQUEST, "userId is required");
        }
        return userId;
    }

    private String requireOrigin(String origin) {
        if (origin == null || origin.isBlank()) {
            throw new AuthException(ErrorCode.INVALID_REQUEST, "origin is required");
        }
        if (!properties.getAllowedOrigins().contains(origin)) {
            throw new AuthException(ErrorCode.INVALID_ORIGIN, "origin is not allowed: " + origin);
        }
        return origin;
    }

    private void requireText(String value, String field, ErrorCode errorCode) {
        if (value == null || value.isBlank()) {
            throw new AuthException(errorCode, field + " is required");
        }
    }

    private enum CommitOutcome {
        COMMITTED, GAP, CLONE, REPLAY, EXPIRED, UNKNOWN, DISABLED
    }

    private static final class OutcomeHolder {
        private CommitOutcome outcome;
    }
}
