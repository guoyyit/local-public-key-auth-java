package com.github.guoyyit.localpublickeyauthjava.web.dto;

public record CredentialView(
        String credentialId,
        String userId,
        String algorithm,
        long signCount,
        boolean enabled,
        long registeredAt,
        long lastUsedAt) {
}
