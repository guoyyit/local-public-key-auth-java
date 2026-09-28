package com.github.guoyyit.localpublickeyauthjava.web.dto;

public final class Dtos {
    private Dtos() {}

    public record RegistrationStartRequest(String userId, String origin) {}

    public record RegistrationStartResponse(String sessionId, String challenge, long expiresAt) {}

    public record RegistrationCompleteRequest(String sessionId, String userId, String origin,
                                              String credentialId, String publicKey, String signature) {}

    public record RegistrationCompleteResponse(String credentialId, String userId, String status) {}

    public record AssertionStartRequest(String userId, String origin) {}

    public record AssertionStartResponse(String challengeId, String challenge, long expiresAt) {}

    public record AssertionVerifyRequest(String challengeId, String userId, String origin,
                                         String credentialId, long counter, String signature) {}

    public record AssertionVerifyResponse(boolean authenticated, String credentialId, long counter) {}

    public record MessageResponse(String status) {}

    public record CredentialView(String credentialId, String userId, String status,
                                 long counter, long createdAt, long updatedAt) {}
}
