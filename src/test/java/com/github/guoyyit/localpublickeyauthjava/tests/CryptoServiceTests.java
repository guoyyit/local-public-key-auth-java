package com.github.guoyyit.localpublickeyauthjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.guoyyit.localpublickeyauthjava.crypto.CryptoService;
import com.github.guoyyit.localpublickeyauthjava.error.AuthException;
import com.github.guoyyit.localpublickeyauthjava.error.ErrorCode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

class CryptoServiceTests {

    private final CryptoService crypto = new CryptoService();

    @Test
    void challengeIsRandomAndDecodable() {
        String c1 = crypto.newChallenge();
        String c2 = crypto.newChallenge();
        assertNotNull(c1);
        assertFalse(c1.equals(c2));
        assertEquals(32, crypto.decodeUrlBase64(c1).length);
    }

    @Test
    void roundTripEd25519() {
        SigningKey key = SigningKey.ed25519();
        byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
        var publicKey = crypto.parsePublicKey("Ed25519", key.publicKeyBase64());
        assertTrue(crypto.verifySignature(publicKey, "Ed25519", data,
                crypto.decodeUrlBase64(key.sign(data))));
        assertFalse(crypto.verifySignature(publicKey, "Ed25519", "other".getBytes(StandardCharsets.UTF_8),
                crypto.decodeUrlBase64(key.sign(data))));
    }

    @Test
    void rawP256SignatureIsConvertedAndVerified() throws Exception {
        // Build a raw r||s signature (not DER) and ensure verification succeeds.
        var generator = java.security.KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();

        byte[] data = "assertion-data".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(data);
        byte[] der = signer.sign();

        // DER signature verifies directly.
        var publicKey = KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(pair.getPublic().getEncoded()));
        assertTrue(crypto.verifySignature(publicKey, "EC_P256", data, der));

        // Convert DER -> raw 64 bytes manually, then verify via the service conversion.
        byte[] raw = derToRaw(der);
        assertEquals(64, raw.length);
        assertTrue(crypto.verifySignature(publicKey, "EC_P256", data, raw));
    }

    @Test
    void rejectsBadBase64AndUnsupportedAlgorithm() {
        AuthException ex = assertThrows(AuthException.class,
                () -> crypto.parsePublicKey("RSA", "AAAA"));
        assertEquals(ErrorCode.UNSUPPORTED_ALGORITHM, ex.errorCode());

        AuthException ex2 = assertThrows(AuthException.class,
                () -> crypto.parsePublicKey("Ed25519", "###not-base64###"));
        assertEquals(ErrorCode.MALFORMED_CREDENTIAL, ex2.errorCode());
    }

    /** Minimal DER ECDSA signature -> raw 32+32 r||s for test purposes. */
    private static byte[] derToRaw(byte[] der) {
        // SEQUENCE tag + length, then INTEGER {len}{r} INTEGER {len}{s}; total <= 72 bytes.
        int rTag = 2;
        int rLen = der[rTag + 1] & 0xff;
        byte[] r = new byte[rLen];
        System.arraycopy(der, rTag + 2, r, 0, rLen);
        int sTag = rTag + 2 + rLen;
        int sLen = der[sTag + 1] & 0xff;
        byte[] s = new byte[sLen];
        System.arraycopy(der, sTag + 2, s, 0, sLen);

        byte[] raw = new byte[64];
        System.arraycopy(r, Math.max(0, r.length - 32), raw, 32 - Math.min(32, r.length), Math.min(32, r.length));
        System.arraycopy(s, Math.max(0, s.length - 32), raw, 64 - Math.min(32, s.length), Math.min(32, s.length));
        return raw;
    }
}
