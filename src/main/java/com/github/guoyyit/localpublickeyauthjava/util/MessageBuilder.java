package com.github.guoyyit.localpublickeyauthjava.util;

import java.nio.charset.StandardCharsets;

/**
 * Builds the canonical byte messages that clients sign.
 *
 * Every field is written as a length-prefixed UTF-8 segment so that fields
 * cannot be confused or injected via concatenation, and the counter is encoded
 * as a fixed 8-byte big-endian value.
 *
 * Registration:
 *   "LPKA-REG-v1" | origin | userId | challenge | credentialId | publicKey
 * Assertion:
 *   "LPKA-AUTH-v1" | origin | userId | challenge | credentialId | counter(8B BE)
 */
public final class MessageBuilder {

    private static final byte[] REG_DOMAIN = "LPKA-REG-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AUTH_DOMAIN = "LPKA-AUTH-v1".getBytes(StandardCharsets.UTF_8);

    private MessageBuilder() {}

    public static byte[] registrationMessage(String origin, String userId, String challenge,
                                             String credentialId, String publicKey) {
        byte[][] parts = new byte[][] {
                REG_DOMAIN,
                bytes(origin),
                bytes(userId),
                bytes(challenge),
                bytes(credentialId),
                bytes(publicKey)
        };
        return join(parts);
    }

    public static byte[] assertionMessage(String origin, String userId, String challenge,
                                          String credentialId, long counter) {
        byte[] head = join(new byte[][] {
                AUTH_DOMAIN,
                bytes(origin),
                bytes(userId),
                bytes(challenge),
                bytes(credentialId)
        });
        byte[] out = new byte[head.length + 8];
        System.arraycopy(head, 0, out, 0, head.length);
        for (int i = 0; i < 8; i++) {
            out[head.length + i] = (byte) (counter >>> (56 - i * 8));
        }
        return out;
    }

    private static byte[] bytes(String s) {
        if (s == null) {
            throw new IllegalArgumentException("message field must not be null");
        }
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] join(byte[][] parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += 4 + part.length;
        }
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] part : parts) {
            int len = part.length;
            out[pos++] = (byte) (len >>> 24);
            out[pos++] = (byte) (len >>> 16);
            out[pos++] = (byte) (len >>> 8);
            out[pos++] = (byte) len;
            System.arraycopy(part, 0, out, pos, len);
            pos += len;
        }
        return out;
    }
}
