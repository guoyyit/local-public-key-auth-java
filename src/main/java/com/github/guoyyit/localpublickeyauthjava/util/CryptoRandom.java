package com.github.guoyyit.localpublickeyauthjava.util;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Secure random generators for challenges and identifiers.
 * Challenges are 32 bytes (256 bits) of entropy, URL-safe base64 encoded;
 * identifiers are 16 bytes (128 bits), sufficient for collision resistance.
 */
public final class CryptoRandom {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private CryptoRandom() {}

    public static String randomId() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }

    public static String randomChallenge() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }
}
