package com.github.guoyyit.localpublickeyauthjava.crypto;

import com.github.guoyyit.localpublickeyauthjava.error.AuthException;
import com.github.guoyyit.localpublickeyauthjava.error.ErrorCode;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Cryptographic primitives used by the authentication service.
 *
 * <p>Supported credential algorithms:
 * <ul>
 *     <li>{@code Ed25519} (RFC 8032, JDK built-in)</li>
 *     <li>{@code EC_P256} (ECDSA over P-256 with SHA-256; DER or raw 64-byte signatures)</li>
 * </ul>
 *
 * <p>Public keys are exchanged as X.509 SubjectPublicKeyInfo bytes in standard Base64.
 * Signatures and challenges use unpadded URL-safe Base64.
 */
public class CryptoService {

    public static final String ALG_ED25519 = "Ed25519";
    public static final String ALG_EC_P256 = "EC_P256";

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private final SecureRandom secureRandom = new SecureRandom();

    /** Generates a 256 bit URL-safe random challenge. */
    public String newChallenge() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return URL_ENCODER.encodeToString(bytes);
    }

    /** Generates a 128 bit URL-safe random identifier. */
    public String newId() {
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        return URL_ENCODER.encodeToString(bytes);
    }

    /** Decodes URL-safe Base64, rejecting null / malformed input. */
    public byte[] decodeUrlBase64(String value) {
        if (value == null || value.isBlank()) {
            throw new AuthException(ErrorCode.INVALID_REQUEST, "missing base64 value");
        }
        try {
            return URL_DECODER.decode(value);
        } catch (IllegalArgumentException ex) {
            throw new AuthException(ErrorCode.MALFORMED_CREDENTIAL, "malformed base64 value", ex);
        }
    }

    /**
     * Parses an X.509 SubjectPublicKeyInfo encoded public key.
     */
    public PublicKey parsePublicKey(String algorithm, String base64Spki) {
        byte[] encoded;
        try {
            encoded = Base64.getDecoder().decode(base64Spki);
        } catch (IllegalArgumentException ex) {
            throw new AuthException(ErrorCode.MALFORMED_CREDENTIAL, "public key is not valid Base64", ex);
        }
        String jcaAlgorithm = jcaKeyAlgorithm(algorithm);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(jcaAlgorithm);
            return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception ex) {
            throw new AuthException(ErrorCode.MALFORMED_CREDENTIAL,
                    "public key is not a valid " + algorithm + " SubjectPublicKeyInfo", ex);
        }
    }

    /**
     * Verifies {@code signature} over {@code data} with the given credential key.
     *
     * @return true when the signature is valid; never throws on signature mismatches
     */
    public boolean verifySignature(PublicKey publicKey, String algorithm, byte[] data, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance(jcaSignatureAlgorithm(algorithm));
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(normalizeSignature(algorithm, signature));
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Canonical bytes signed by the client when completing registration.
     *
     * <pre>
     * LOCAL-PK-AUTH-V1:REGISTER\n
     * userId={userId}\n
     * origin={origin}\n
     * challenge={challenge}\n
     * credentialId={credentialId}
     * </pre>
     */
    public byte[] registrationSignedData(String userId, String origin, String challenge, String credentialId) {
        String canonical = "LOCAL-PK-AUTH-V1:REGISTER\n"
                + "userId=" + userId + "\n"
                + "origin=" + origin + "\n"
                + "challenge=" + challenge + "\n"
                + "credentialId=" + credentialId;
        return canonical.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Canonical bytes signed by the client when answering a login challenge.
     *
     * <pre>
     * LOCAL-PK-AUTH-V1:ASSERT\n
     * userId={userId}\n
     * origin={origin}\n
     * challenge={challenge}\n
     * credentialId={credentialId}\n
     * signCount={signCount}
     * </pre>
     */
    public byte[] assertionSignedData(String userId, String origin, String challenge,
                                      String credentialId, long signCount) {
        String canonical = "LOCAL-PK-AUTH-V1:ASSERT\n"
                + "userId=" + userId + "\n"
                + "origin=" + origin + "\n"
                + "challenge=" + challenge + "\n"
                + "credentialId=" + credentialId + "\n"
                + "signCount=" + signCount;
        return canonical.getBytes(StandardCharsets.UTF_8);
    }

    private String jcaKeyAlgorithm(String algorithm) {
        if (ALG_ED25519.equals(algorithm)) {
            return "Ed25519";
        }
        if (ALG_EC_P256.equals(algorithm)) {
            return "EC";
        }
        throw new AuthException(ErrorCode.UNSUPPORTED_ALGORITHM, "unsupported algorithm: " + algorithm);
    }

    private String jcaSignatureAlgorithm(String algorithm) {
        if (ALG_ED25519.equals(algorithm)) {
            return "Ed25519";
        }
        if (ALG_EC_P256.equals(algorithm)) {
            return "SHA256withECDSA";
        }
        throw new AuthException(ErrorCode.UNSUPPORTED_ALGORITHM, "unsupported algorithm: " + algorithm);
    }

    /**
     * Accepts both DER encoded and raw 64 byte concatenated R||S ECDSA signatures.
     */
    private byte[] normalizeSignature(String algorithm, byte[] signature) throws Exception {
        if (!ALG_EC_P256.equals(algorithm) || signature.length != 64) {
            // Ed25519 signatures, or already DER encoded ECDSA signatures, are used as-is.
            return signature;
        }
        // Raw fixed length r||s -> DER SEQUENCE expected by SHA256withECDSA
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);
        byte[] rDer = toDerInteger(r);
        byte[] sDer = toDerInteger(s);
        int contentLength = rDer.length + sDer.length;
        byte[] der = new byte[2 + contentLength];
        int pos = 0;
        der[pos++] = 0x30;
        der[pos++] = (byte) contentLength;
        System.arraycopy(rDer, 0, der, pos, rDer.length);
        pos += rDer.length;
        System.arraycopy(sDer, 0, der, pos, sDer.length);
        return der;
    }

    private static byte[] toDerInteger(byte[] unsigned) {
        int start = 0;
        while (start < unsigned.length - 1 && unsigned[start] == 0) {
            start++;
        }
        int len = unsigned.length - start;
        boolean needPad = (unsigned[start] & 0x80) != 0;
        byte[] out = new byte[2 + len + (needPad ? 1 : 0)];
        int pos = 0;
        out[pos++] = 0x02;
        out[pos++] = (byte) (len + (needPad ? 1 : 0));
        if (needPad) {
            out[pos++] = 0;
        }
        System.arraycopy(unsigned, start, out, pos, len);
        return out;
    }
}
