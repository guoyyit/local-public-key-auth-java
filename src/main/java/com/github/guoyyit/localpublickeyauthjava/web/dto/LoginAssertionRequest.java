package com.github.guoyyit.localpublickeyauthjava.web.dto;

/**
 * @param signature Base64 signature over the canonical assertion string
 * @param signCount monotonic credential usage counter from the authenticator
 */
public record LoginAssertionRequest(
        String challengeId,
        String userId,
        String origin,
        String credentialId,
        String signature,
        long signCount) {
}
