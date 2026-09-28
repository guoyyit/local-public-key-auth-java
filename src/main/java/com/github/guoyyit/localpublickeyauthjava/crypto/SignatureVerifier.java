package com.github.guoyyit.localpublickeyauthjava.crypto;

import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Verifies Ed25519 signatures.
 *
 * Registered public keys are X.509/SPKI encoded keys, base64 (standard or
 * URL-safe) encoded. Client signatures are raw 64-byte Ed25519 signatures,
 * base64 encoded.
 */
@Component
public class SignatureVerifier {

    private static final int ED25519_SIGNATURE_LENGTH = 64;

    public boolean verify(String publicKeyBase64, byte[] message, String signatureBase64) {
        try {
            PublicKey publicKey = parsePublicKey(publicKeyBase64);
            byte[] signature = decodeBase64(signatureBase64);
            if (signature.length != ED25519_SIGNATURE_LENGTH) {
                return false;
            }
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Validates that the supplied string is a parseable Ed25519 public key.
     *
     * @throws IllegalArgumentException if the key cannot be parsed
     */
    public void validatePublicKey(String publicKeyBase64) {
        try {
            parsePublicKey(publicKeyBase64);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid Ed25519 public key: " + e.getMessage(), e);
        }
    }

    private static PublicKey parsePublicKey(String publicKeyBase64) throws Exception {
        byte[] keyBytes = decodeBase64(publicKeyBase64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("Ed25519").generatePublic(spec);
    }

    private static byte[] decodeBase64(String value) {
        // accept both standard and URL-safe base64, with or without padding
        String compact = value.replaceAll("\\s+", "");
        try {
            return Base64.getDecoder().decode(compact);
        } catch (IllegalArgumentException e) {
            return Base64.getUrlDecoder().decode(compact);
        }
    }
}
