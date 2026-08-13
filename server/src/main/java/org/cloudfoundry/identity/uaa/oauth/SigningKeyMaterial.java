package org.cloudfoundry.identity.uaa.oauth;

import com.nimbusds.jose.JWSSigner;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Everything a {@link KeyInfo} needs that differs between a locally held PEM
 * key and a key held in an external key store.
 *
 * @param signer      signs a JWS payload; may delegate to an external process
 * @param publicKey   the public half, used to build the JWK for /token_keys
 * @param algorithm   JWS algorithm name, e.g. RS256 or ES256
 * @param certificate optional X.509 certificate for x5c/x5t claims
 */
public record SigningKeyMaterial(
        JWSSigner signer,
        PublicKey publicKey,
        String algorithm,
        Optional<X509Certificate> certificate) {
}
