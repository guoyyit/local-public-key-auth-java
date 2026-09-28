package com.github.guoyyit.localpublickeyauthjava.service;

import com.github.guoyyit.localpublickeyauthjava.crypto.SignatureVerifier;
import com.github.guoyyit.localpublickeyauthjava.model.ApiException;
import com.github.guoyyit.localpublickeyauthjava.model.Credential;
import com.github.guoyyit.localpublickeyauthjava.model.CredentialStatus;
import com.github.guoyyit.localpublickeyauthjava.model.ErrorCode;
import com.github.guoyyit.localpublickeyauthjava.model.RegistrationSession;
import com.github.guoyyit.localpublickeyauthjava.store.JsonFileStore;
import com.github.guoyyit.localpublickeyauthjava.util.MessageBuilder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Credential registration and lifecycle management.
 *
 * <p>Registration validates, in one atomic store transaction:
 * <ol>
 *   <li>field formats (user / credential id / public key / signature),</li>
 *   <li>the registration session: existence, user binding, origin, expiry,
 *       single use,</li>
 *   <li>credential-id uniqueness (a credential belongs to exactly one user),</li>
 *   <li>the possession signature over the canonical registration message.</li>
 * </ol>
 * Only when all checks pass is the session consumed <em>and</em> the credential
 * stored in the same persisted write, so a failed registration leaves no
 * half-written state.
 */
@Service
public class CredentialService {

    private static final Pattern CREDENTIAL_ID = Pattern.compile("[A-Za-z0-9_-]{8,128}");
    private static final Pattern USER_ID = Pattern.compile("[A-Za-z0-9_.@-]{1,128}");

    private final JsonFileStore store;
    private final SignatureVerifier verifier;
    private final TimeProvider time;
    private final ChallengeService challenges;

    public CredentialService(JsonFileStore store, SignatureVerifier verifier,
                             TimeProvider time, ChallengeService challenges) {
        this.store = store;
        this.verifier = verifier;
        this.time = time;
        this.challenges = challenges;
    }

    public Credential register(String userId, String sessionId, String origin, String credentialId,
                               String publicKey, String signature) {
        requireText(userId, "userId");
        requireText(sessionId, "sessionId");
        requireText(origin, "origin");
        requireText(credentialId, "credentialId");
        requireText(publicKey, "publicKey");
        requireText(signature, "signature");
        if (!USER_ID.matcher(userId).matches()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "invalid userId format");
        }
        if (!CREDENTIAL_ID.matcher(credentialId).matches()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "invalid credentialId format");
        }
        try {
            verifier.validatePublicKey(publicKey);
        } catch (IllegalArgumentException e) {
            throw new ApiException(ErrorCode.INVALID_PUBLIC_KEY, e.getMessage());
        }

        // All validation, challenge consumption and persistence happen in one
        // atomic mutation: concurrent completion attempts for the same session
        // are serialized and only one can succeed (no TOCTOU replay window).
        long now = time.nowMillis();
        return store.mutate(data -> {
            RegistrationSession session = challenges.takeRegistration(data, sessionId, userId, origin);

            Credential existing = data.getCredentials().get(credentialId);
            if (existing != null) {
                throw new ApiException(ErrorCode.CREDENTIAL_ALREADY_EXISTS,
                        "credentialId is already registered");
            }

            byte[] message = MessageBuilder.registrationMessage(
                    origin, userId, session.getChallenge(), credentialId, publicKey);
            if (!verifier.verify(publicKey, message, signature)) {
                throw new ApiException(ErrorCode.INVALID_SIGNATURE,
                        "registration signature does not verify");
            }

            Credential credential = new Credential(credentialId, userId, publicKey, 0L,
                    CredentialStatus.ACTIVE, now, now);
            data.getCredentials().put(credentialId, credential);
            return credential;
        });
    }

    public List<Credential> list(String userId) {
        requireText(userId, "userId");
        return store.read(data -> data.getCredentials().values().stream()
                .filter(c -> c.getUserId().equals(userId))
                .toList());
    }

    /**
     * Disable a credential: it can no longer authenticate, but the other
     * credentials of the user are unaffected. Idempotent for active credentials.
     */
    public void disable(String userId, String credentialId) {
        changeStatus(userId, credentialId, CredentialStatus.DISABLED);
    }

    /**
     * Permanently revoke a credential (e.g. after clone detection or explicit
     * deregistration). Revoked credentials can never authenticate again.
     */
    public void revoke(String userId, String credentialId) {
        changeStatus(userId, credentialId, CredentialStatus.REVOKED);
    }

    private void changeStatus(String userId, String credentialId, CredentialStatus target) {
        requireText(userId, "userId");
        requireText(credentialId, "credentialId");
        long now = time.nowMillis();
        store.mutate(data -> {
            Credential credential = requireOwned(data, userId, credentialId);
            credential.setStatus(target);
            credential.setUpdatedAt(now);
            return null;
        });
    }

    public Credential findActive(String userId, String credentialId) {
        return store.read(data -> {
            Credential credential = requireOwned(data, userId, credentialId);
            if (credential.getStatus() != CredentialStatus.ACTIVE) {
                throw new ApiException(ErrorCode.CREDENTIAL_REVOKED,
                        "credential is " + credential.getStatus().name().toLowerCase());
            }
            return credential;
        });
    }

    private static Credential requireOwned(com.github.guoyyit.localpublickeyauthjava.store.StoreData data,
                                           String userId, String credentialId) {
        Credential credential = data.getCredentials().get(credentialId);
        if (credential == null) {
            throw new ApiException(ErrorCode.CREDENTIAL_NOT_FOUND, "credential not found");
        }
        if (!credential.getUserId().equals(userId)) {
            // do not reveal existence to a non-owner
            throw new ApiException(ErrorCode.CREDENTIAL_NOT_FOUND, "credential not found");
        }
        return credential;
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, field + " is required");
        }
    }
}
