package org.cloudfoundry.identity.uaa.oauth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;

import java.security.PublicKey;

/**
 * Resolves keys whose private material is configured inline as PEM.
 *
 * <p>This is the historical behaviour and remains the default. It is not
 * suitable where private key material must not be readable on the host,
 * since the key is present in configuration and in process memory.
 */
public class LocalPemSigningKeyProvider implements SigningKeyProvider {

    @Override
    public boolean supports(TokenPolicy.KeyInformation key) {
        return !UaaStringUtils.isEmpty(key.getSigningKey());
    }

    @Override
    public SigningKeyMaterial resolve(TokenPolicy.KeyInformation key, String algorithm) {
        String signingKey = key.getSigningKey().trim();
        KeyInfo delegate = new KeyInfo(
                "unused",
                signingKey,
                "https://localhost",
                algorithm != null ? algorithm : key.getSigningAlg(),
                key.getSigningCert());

        return new SigningKeyMaterial(
                delegate.getSigner(),
                publicKeyOf(signingKey),
                delegate.algorithm(),
                delegate.verifierCertificate());
    }

    private static PublicKey publicKeyOf(String pem) {
        try {
            JWK jwk = JWK.parseFromPEMEncodedObjects(pem);
            if (jwk.getKeyType().getValue().startsWith("RSA")) {
                return jwk.toRSAKey().toPublicKey();
            }
            return jwk.toECKey().toPublicKey();
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Unreadable signing key", e);
        }
    }
}
