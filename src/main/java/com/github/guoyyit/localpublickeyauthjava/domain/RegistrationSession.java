package com.github.guoyyit.localpublickeyauthjava.domain;

/**
 * A server side registration session carrying a challenge bound to a user and an origin.
 */
public record RegistrationSession(
        String sessionId,
        String userId,
        String origin,
        String challenge,
        long createdAt,
        long expiresAt,
        boolean consumed) {
}
