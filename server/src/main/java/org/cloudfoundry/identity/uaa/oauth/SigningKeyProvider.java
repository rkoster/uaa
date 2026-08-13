package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.zone.TokenPolicy;

/**
 * Resolves a configured signing key into something that can sign.
 *
 * <p>Implementations are consulted in order; the first whose
 * {@link #supports} returns true is used. This allows a deployment to mix
 * locally configured keys with keys held in an external key store, which is
 * what makes migration between the two possible without downtime.
 */
public interface SigningKeyProvider {

    /**
     * @return true if this provider can resolve the given key configuration
     */
    boolean supports(TokenPolicy.KeyInformation key);

    /**
     * @param key       the configured key
     * @param algorithm requested JWS algorithm, or null to use the key's default
     * @return the signer and public key material
     * @throws IllegalArgumentException if the configuration is unusable
     */
    SigningKeyMaterial resolve(TokenPolicy.KeyInformation key, String algorithm);
}
