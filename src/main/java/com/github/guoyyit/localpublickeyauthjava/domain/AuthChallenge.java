package com.github.guoyyit.localpublickeyauthjava.domain;

/**
 * A single use login challenge bound to a user and an origin.
 */
public record AuthChallenge(
        String challengeId,
        String userId,
        String origin,
        String challenge,
        long createdAt,
        long expiresAt,
        boolean consumed) {
}
