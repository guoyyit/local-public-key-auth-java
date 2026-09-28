package com.github.guoyyit.localpublickeyauthjava.web.dto;

public record LoginStartResponse(
        String challengeId,
        String userId,
        String challenge,
        long expiresAt) {
}
