package com.github.guoyyit.localpublickeyauthjava.domain;

/**
 * A registered public key credential bound to a user.
 *
 * @param credentialId    client supplied unique credential identifier
 * @param userId          owning user identifier
 * @param algorithm       key algorithm, e.g. {@code Ed25519} or {@code EC_P256}
 * @param publicKeyBase64 X.509 SubjectPublicKeyInfo encoded public key, standard Base64
 * @param signCount       last accepted credential signature counter
 * @param enabled         whether the credential may be used for assertions
 * @param registeredAt    registration time in epoch millis
 * @param lastUsedAt      last successful assertion time in epoch millis ({@code 0} if never)
 */
public record Credential(
        String credentialId,
        String userId,
        String algorithm,
        String publicKeyBase64,
        long signCount,
        boolean enabled,
        long registeredAt,
        long lastUsedAt) {
}
