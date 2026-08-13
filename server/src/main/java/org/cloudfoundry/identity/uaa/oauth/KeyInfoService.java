/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.impl.config.LegacyTokenKey;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.springframework.util.StringUtils;

import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;

public class KeyInfoService {
    private final String uaaBaseURL;
    private final List<SigningKeyProvider> providers;
    private final Map<CacheKey, KeyInfo> cache = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<CacheKey, KeyInfo> eldest) {
                    return size() > 128;
                }
            });

    public KeyInfoService(String uaaBaseURL) {
        this(uaaBaseURL, List.of(new LocalPemSigningKeyProvider()));
    }

    public KeyInfoService(String uaaBaseURL, List<SigningKeyProvider> providers) {
        this.uaaBaseURL = uaaBaseURL;
        this.providers = providers;
    }

    /**
     * Identifies a resolved key by its content rather than by name, so a
     * configuration change produces a different entry and stale entries simply
     * age out. The zone-specific URL is included because it is baked into the
     * key's published location.
     */
    private record CacheKey(String keyId, String signingKey, String signingKeyRef,
                            String signingAlg, String signingCert, String keyUrl) {
    }

    public KeyInfo getKey(String keyId, String sigAlg) {
        return getKeys(sigAlg).get(keyId);
    }

    public KeyInfo getKey(String keyId) {
        return getKeys().get(keyId);
    }

    public Map<String, KeyInfo> getKeys() {
        return getKeys(null);
    }

    public Map<String, KeyInfo> getKeys(String sigAlg) {
        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        if (config == null || config.getTokenPolicy().getKeys() == null || config.getTokenPolicy().getKeys().isEmpty()) {
            config = IdentityZoneHolder.getUaaZone().getConfig();
        }

        Map<String, KeyInfo> keys = new HashMap<>();
        String keyUrl = addSubdomainToUrl(uaaBaseURL, IdentityZoneHolder.get().getSubdomain());

        for (Map.Entry<String, TokenPolicy.KeyInformation> entry : config.getTokenPolicy().getKeys().entrySet()) {
            TokenPolicy.KeyInformation keyInformation = entry.getValue();
            CacheKey cacheKey = new CacheKey(
                    entry.getKey(),
                    keyInformation.getSigningKey(),
                    keyInformation.getSigningKeyRef(),
                    sigAlg != null ? sigAlg : keyInformation.getSigningAlg(),
                    keyInformation.getSigningCert(),
                    keyUrl);

            keys.put(entry.getKey(), cache.computeIfAbsent(cacheKey,
                    unused -> resolve(entry.getKey(), keyInformation, sigAlg, keyUrl)));
        }

        if (keys.isEmpty()) {
            keys.put(LegacyTokenKey.LEGACY_TOKEN_KEY_ID, LegacyTokenKey.getLegacyTokenKeyInfo());
        }

        return keys;
    }

    private KeyInfo resolve(String keyId, TokenPolicy.KeyInformation keyInformation,
                            String sigAlg, String keyUrl) {
        for (SigningKeyProvider provider : providers) {
            if (provider.supports(keyInformation)) {
                return new KeyInfo(keyId, keyUrl, provider.resolve(keyInformation, sigAlg));
            }
        }
        // Symmetric (HMAC) keys have no SigningKeyProvider today -- SigningKeyMaterial has no
        // representation for a shared secret, only a PublicKey. Preserve the historical behaviour
        // for this case by falling back to the original construction path.
        if (!UaaStringUtils.isEmpty(keyInformation.getSigningKey())) {
            return KeyInfoBuilder.build(keyId, keyInformation.getSigningKey(), keyUrl,
                    sigAlg != null ? sigAlg : keyInformation.getSigningAlg(),
                    keyInformation.getSigningCert());
        }
        throw new IllegalArgumentException(
                "No signing key provider can handle key " + keyId
                        + "; set exactly one of signingKey or signingKeyRef");
    }

    public KeyInfo getActiveKey() {
        return getKeys().get(getActiveKeyId());
    }

    private String getActiveKeyId() {
        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        if (config == null) {
            return IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
        }
        String activeKeyId = config.getTokenPolicy().getActiveKeyId();

        Map<String, KeyInfo> keys;
        if (!StringUtils.hasText(activeKeyId) && (keys = getKeys()).size() == 1) {
            activeKeyId = keys.keySet().stream().findAny().get();
        }

        if (!StringUtils.hasText(activeKeyId)) {
            activeKeyId = IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
        }

        if (!StringUtils.hasText(activeKeyId)) {
            activeKeyId = LegacyTokenKey.LEGACY_TOKEN_KEY_ID;
        }

        return activeKeyId;
    }

    public String getTokenEndpointUrl() throws URISyntaxException {
        IdentityZone identityZone = IdentityZoneHolder.get();
        String issuer = Optional.ofNullable(identityZone.getConfig())
                .map(IdentityZoneConfiguration::getIssuer)
                .orElse(uaaBaseURL);
        return UaaTokenUtils.constructTokenEndpointUrl(issuer, identityZone);
    }
}
