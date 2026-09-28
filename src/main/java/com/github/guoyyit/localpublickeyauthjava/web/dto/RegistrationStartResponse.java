package com.github.guoyyit.localpublickeyauthjava.web.dto;

public record RegistrationStartResponse(
        String sessionId,
        String userId,
        String challenge,
        long expiresAt) {
}
