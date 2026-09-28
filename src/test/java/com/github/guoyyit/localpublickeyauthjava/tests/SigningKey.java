package com.github.guoyyit.localpublickeyauthjava.tests;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * Test authenticator: holds a credential key pair and signs canonical messages
 * exactly like a client would.
 */
public final class SigningKey {

    private final String algorithm;
    private final KeyPair keyPair;
    private long counter;

    private SigningKey(String algorithm, KeyPair keyPair) {
        this.algorithm = algorithm;
        this.keyPair = keyPair;
        this.counter = 0;
    }

    public static SigningKey ed25519() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            return new SigningKey("Ed25519", generator.generateKeyPair());
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    public static SigningKey ecP256() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return new SigningKey("EC_P256", generator.generateKeyPair());
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    public String algorithm() {
        return algorithm;
    }

    public String publicKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public String sign(byte[] data) {
        return sign(data, keyPair.getPrivate());
    }

    public String sign(byte[] data, PrivateKey privateKey) {
        try {
            Signature signer = Signature.getInstance(
                    "Ed25519".equals(algorithm) ? "Ed25519" : "SHA256withECDSA");
            signer.initSign(privateKey);
            signer.update(data);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    public PrivateKey privateKey() {
        return keyPair.getPrivate();
    }

    /** Returns the next strictly increasing authenticator counter. */
    public long nextCounter() {
        return ++counter;
    }

    public long currentCounter() {
        return counter;
    }
}
