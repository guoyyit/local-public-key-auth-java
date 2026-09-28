package com.github.guoyyit.localpublickeyauthjava.web.dto;

public record LoginAssertionResponse(
        String userId,
        String credentialId,
        long signCount,
        String status) {
}
