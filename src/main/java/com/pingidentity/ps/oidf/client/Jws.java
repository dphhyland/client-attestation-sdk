package com.pingidentity.ps.oidf.client;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

/**
 * Internal helper: signs a JSON payload into a compact JWS with an explicit {@code typ} header, keyed by a
 * {@link SigningKeyPair}. When {@code embedPublicJwk} is set the public key is carried in a {@code jwk}
 * header (as DPoP requires); otherwise the key's thumbprint {@code kid} is set.
 */
final class Jws {

    private Jws() {
    }

    static String sign(String payloadJson, SigningKeyPair key, String typ, boolean embedPublicJwk) {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payloadJson);
        jws.setAlgorithmHeaderValue(key.algorithm());
        jws.setHeader("typ", typ);
        if (embedPublicJwk) {
            jws.getHeaders().setJwkHeaderValue("jwk", key.publicJsonWebKey());
        } else {
            jws.setKeyIdHeaderValue(key.keyId());
        }
        jws.setKey(key.privateKey());
        try {
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new IllegalStateException("JWS signing failed", e);
        }
    }
}
