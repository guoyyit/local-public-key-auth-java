package com.github.guoyyit.localpublickeyauthjava.web.dto;

/**
 * @param signature Base64 signature over the canonical registration string
 */
public record RegistrationCompleteRequest(
        String sessionId,
        String userId,
        String origin,
        String credentialId,
        String algorithm,
        String publicKey,
        String signature) {
}
