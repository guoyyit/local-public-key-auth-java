package com.github.guoyyit.localpublickeyauthjava.tests.support;

import com.github.guoyyit.localpublickeyauthjava.util.MessageBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;

/**
 * Generates Ed25519 key pairs and produces client-style signatures for tests.
 */
public final class TestKeys {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private TestKeys() {}

    public static KeyPair generate() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String publicKey(KeyPair kp) {
        return B64.encodeToString(kp.getPublic().getEncoded());
    }

    public static String sign(KeyPair kp, byte[] message) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(kp.getPrivate());
            sig.update(message);
            return B64.encodeToString(sig.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] registrationMessage(String origin, String userId, String challenge,
                                             String credentialId, String publicKey) {
        return MessageBuilder.registrationMessage(origin, userId, challenge, credentialId, publicKey);
    }

    public static byte[] assertionMessage(String origin, String userId, String challenge,
                                          String credentialId, long counter) {
        return MessageBuilder.assertionMessage(origin, userId, challenge, credentialId, counter);
    }
}
