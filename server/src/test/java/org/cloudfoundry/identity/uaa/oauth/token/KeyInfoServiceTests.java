package org.cloudfoundry.identity.uaa.oauth.token;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.impl.config.LegacyTokenKey;
import org.cloudfoundry.identity.uaa.oauth.FakeSigningService;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.LocalPemSigningKeyProvider;
import org.cloudfoundry.identity.uaa.oauth.RemoteSigningKeyProvider;
import org.cloudfoundry.identity.uaa.oauth.SigningKeyMaterial;
import org.cloudfoundry.identity.uaa.oauth.SigningKeyProvider;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.util.ReflectionTestUtils;

import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class KeyInfoServiceTests {
    private static final String SIGNING_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXAIBAAKBgQDErZsZY70QAa7WdDD6eOv3RLBA4I5J0zZOiXMzoFB5yh64q0sm
            ESNtV4payOYE5TnHxWjMo0y7gDsGjI1omAG6wgfyp63I9WcLX7FDLyee43fG5+b9
            roofosL+OzJSXESSulsT9Y1XxSFFM5RMu4Ie9uM4/izKLCsAKiggMhnAmQIDAQAB
            AoGAAs2OllALk7zSZxAE2qz6f+2krWgF3xt5fKkM0UGJpBKzWWJnkcVQwfArcpvG
            W2+A4U347mGtaEatkKxUH5d6/s37jfRI7++HFXcLf6QJPmuE3+FtB2mX0lVJoaJb
            RLh+tOtt4ZJRAt/u6RjUCVNpDnJB6NZ032bpL3DijfNkRuECQQDkJR+JJPUpQGoI
            voPqcLl0i1tLX93XE7nu1YuwdQ5SmRaS0IJMozoBLBfFNmCWlSHaQpBORc38+eGC
            J9xsOrBNAkEA3LD1JoNI+wPSo/o71TED7BoVdwCXLKPqm0TnTr2EybCUPLNoff8r
            Ngm51jXc8mNvUkBtYiPfMKzpdqqFBWXXfQJAQ7D0E2gAybWQAHouf7/kdrzmYI3Y
            L3lt4HxBzyBcGIvNk9AD6SNBEZn4j44byHIFMlIvqNmzTY0CqPCUyRP8vQJBALXm
            ANmygferKfXP7XsFwGbdBO4mBXRc0qURwNkMqiMXMMdrVGftZq9Oiua9VJRQUtPn
            mIC4cmCLVI5jc+qEC30CQE+eOXomzxNNPxVnIp5k5f+savOWBBu83J2IoT2znnGb
            wTKZHjWybPHsW2q8Z6Moz5dvE+XMd11c5NtIG2/L97I=
            -----END RSA PRIVATE KEY-----""";
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    private KeyInfoService keyInfoService;

    @BeforeAll
    static void setupLegacyKey() {
        LegacyTokenKey.setLegacySigningKey("testLegacyKey", "https://localhost/uaa", null, null);
    }

    @BeforeEach
    void setup() {
        keyInfoService = new KeyInfoService("https://localhost/uaa");
    }

    @Test
    void signedProviderSymmetricKeys() {
        String keyId = generator.generate();
        configureDefaultZoneKeys(Collections.singletonMap(keyId, "testkey"));

        KeyInfo key = keyInfoService.getKey(keyId);
        assertThat(key.getSigner()).isNotNull();
        assertThat(key.getVerifier()).isNotNull();
    }

    @Test
    void signedProviderAsymmetricKeys() {
        String signingKey = """
                -----BEGIN RSA PRIVATE KEY-----
                MIICXAIBAAKBgQDErZsZY70QAa7WdDD6eOv3RLBA4I5J0zZOiXMzoFB5yh64q0sm
                ESNtV4payOYE5TnHxWjMo0y7gDsGjI1omAG6wgfyp63I9WcLX7FDLyee43fG5+b9
                roofosL+OzJSXESSulsT9Y1XxSFFM5RMu4Ie9uM4/izKLCsAKiggMhnAmQIDAQAB
                AoGAAs2OllALk7zSZxAE2qz6f+2krWgF3xt5fKkM0UGJpBKzWWJnkcVQwfArcpvG
                W2+A4U347mGtaEatkKxUH5d6/s37jfRI7++HFXcLf6QJPmuE3+FtB2mX0lVJoaJb
                RLh+tOtt4ZJRAt/u6RjUCVNpDnJB6NZ032bpL3DijfNkRuECQQDkJR+JJPUpQGoI
                voPqcLl0i1tLX93XE7nu1YuwdQ5SmRaS0IJMozoBLBfFNmCWlSHaQpBORc38+eGC
                J9xsOrBNAkEA3LD1JoNI+wPSo/o71TED7BoVdwCXLKPqm0TnTr2EybCUPLNoff8r
                Ngm51jXc8mNvUkBtYiPfMKzpdqqFBWXXfQJAQ7D0E2gAybWQAHouf7/kdrzmYI3Y
                L3lt4HxBzyBcGIvNk9AD6SNBEZn4j44byHIFMlIvqNmzTY0CqPCUyRP8vQJBALXm
                ANmygferKfXP7XsFwGbdBO4mBXRc0qURwNkMqiMXMMdrVGftZq9Oiua9VJRQUtPn
                mIC4cmCLVI5jc+qEC30CQE+eOXomzxNNPxVnIp5k5f+savOWBBu83J2IoT2znnGb
                wTKZHjWybPHsW2q8Z6Moz5dvE+XMd11c5NtIG2/L97I=
                -----END RSA PRIVATE KEY-----""";
        String keyId = generator.generate();
        configureDefaultZoneKeys(Collections.singletonMap(keyId, signingKey));
        KeyInfo key = keyInfoService.getKey(keyId);
        assertThat(key.getSigner()).isNotNull();
        assertThat(key.getVerifier()).isNotNull();
        JWKSet jwkSet;
        List<JWK> jwkList = new ArrayList<>();
        keyInfoService.getKeys().values().forEach(keyInfo -> {
            try {
                jwkList.add(JWK.parse(keyInfo.getJwkMap()));
            } catch (ParseException _) {
                // ignore
            }
        });
        jwkSet = new JWKSet(jwkList);
        assertThat(jwkSet).isNotNull();
        assertThat(jwkSet.size()).isOne();
    }

    @Test
    void signedProviderAsymmetricKeysShouldAddKeyURL() {
        String keyId = generator.generate();
        configureDefaultZoneKeys(Collections.singletonMap(keyId, SIGNING_KEY));

        KeyInfo key = keyInfoService.getKey(keyId);
        assertThat(key.getSigner()).isNotNull();
        assertThat(key.getVerifier()).isNotNull();

        assertThat(key.keyURL()).isEqualTo("https://localhost/uaa/token_keys");
    }

    @Test
    void signedProviderAsymmetricKeysShouldAddKeyURLForCorrectZone() {
        String keyId = generator.generate();
        IdentityZoneHolder.clear();
        IdentityZoneProvisioning provisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);

        IdentityZone zone = IdentityZone.getUaa();
        zone.setSubdomain("subdomain");

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap(keyId, SIGNING_KEY));
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(provisioning.retrieve("uaa")).thenReturn(zone);

        KeyInfo key = keyInfoService.getKey(keyId);
        assertThat(key.getSigner()).isNotNull();
        assertThat(key.getVerifier()).isNotNull();

        assertThat(key.keyURL()).isEqualTo("https://subdomain.localhost/uaa/token_keys");
    }

    @Test
    void activeKeyFallsBackToLegacyKey() {
        configureDefaultZoneKeys(Collections.emptyMap());

        assertThat(keyInfoService.getActiveKey().keyId()).isEqualTo(LegacyTokenKey.LEGACY_TOKEN_KEY_ID);
        assertThat(keyInfoService.getActiveKey().verifierKey()).isEqualTo("testLegacyKey");
    }

    @Test
    void tokenEndpointUrl_whenIssuerIsNull() throws Exception {
        configureDefaultZoneKeys(Collections.emptyMap());

        assertThat(keyInfoService.getTokenEndpointUrl()).isEqualTo("https://localhost/uaa/oauth/token");
    }

    @Test
    void tokenEndpointUrl_whenIssuerSet() throws Exception {
        configureDefaultZoneKeys(Collections.emptyMap());
        IdentityZoneHolder.get().getConfig().setIssuer("https://issuer.set/uaa");

        assertThat(keyInfoService.getTokenEndpointUrl()).isEqualTo("https://issuer.set/uaa/oauth/token");
    }

    @Test
    void resolvesARemoteKeyOnlyOnceAcrossRepeatedLookups() throws Exception {
        try (FakeSigningService service = new FakeSigningService()) {
            RemoteSigningKeyProvider remote =
                    new RemoteSigningKeyProvider(service.channel(), Duration.ofSeconds(2), 3);
            KeyInfoService remoteKeyInfoService = new KeyInfoService(
                    "https://localhost",
                    List.of(new LocalPemSigningKeyProvider(), remote));

            TokenPolicy.KeyInformation keyInformation = new TokenPolicy.KeyInformation();
            keyInformation.setSigningKeyRef(FakeSigningService.KEY_REF);
            configureDefaultZoneKeyInformation(Map.of("remote-kid", keyInformation), "remote-kid");

            remoteKeyInfoService.getKeys();
            remoteKeyInfoService.getKeys();
            remoteKeyInfoService.getActiveKey();

            assertThat(service.publicKeyCallCount()).isEqualTo(1);
        }
    }

    @Test
    void resolvingOneZonesKeyDoesNotBlockAConcurrentLookupOfAnAlreadyCachedKeyInAnotherZone() throws Exception {
        // getKeys() resolves every key configured in the CURRENT zone in one call, so the "fast"
        // and "blocking" keys must live in different zones' token policies -- otherwise looking up
        // either one would resolve both in the same call, on the same thread, and the test would
        // not isolate the behaviour it's trying to prove.
        CountDownLatch resolutionStarted = new CountDownLatch(1);
        CountDownLatch releaseResolution = new CountDownLatch(1);

        SigningKeyProvider blockingProvider = new SigningKeyProvider() {
            @Override
            public boolean supports(TokenPolicy.KeyInformation key) {
                return "blocking-ref".equals(key.getSigningKeyRef());
            }

            @Override
            public SigningKeyMaterial resolve(TokenPolicy.KeyInformation key, String algorithm) {
                resolutionStarted.countDown();
                try {
                    if (!releaseResolution.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("test did not release the blocked resolution in time");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                }
                TokenPolicy.KeyInformation inline = new TokenPolicy.KeyInformation();
                inline.setSigningKey(SIGNING_KEY);
                return new LocalPemSigningKeyProvider().resolve(inline, algorithm);
            }
        };

        KeyInfoService service = new KeyInfoService(
                "https://localhost/uaa",
                List.of(new LocalPemSigningKeyProvider(), blockingProvider));

        IdentityZone fastZone = zoneNamed("fast-zone", "fast-key", inlineKey(SIGNING_KEY));
        IdentityZone blockingZone = zoneNamed("blocking-zone", "blocking-key", referencedKey("blocking-ref"));

        IdentityZoneHolder.clear();
        try {
            // Pre-warm the cache entry for the fast zone's key so the lookup below is a cache hit.
            IdentityZoneHolder.set(fastZone);
            service.getKey("fast-key");
            IdentityZoneHolder.clear();

            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<?> blockingLookup = executor.submit(() -> {
                    IdentityZoneHolder.set(blockingZone);
                    try {
                        return service.getKey("blocking-key");
                    } finally {
                        IdentityZoneHolder.clear();
                    }
                });
                assertThat(resolutionStarted.await(2, TimeUnit.SECONDS))
                        .as("the blocking provider should have been entered")
                        .isTrue();

                CountDownLatch fastLookupCompleted = new CountDownLatch(1);
                Future<KeyInfo> fastLookup = executor.submit(() -> {
                    IdentityZoneHolder.set(fastZone);
                    try {
                        KeyInfo result = service.getKey("fast-key");
                        fastLookupCompleted.countDown();
                        return result;
                    } finally {
                        IdentityZoneHolder.clear();
                    }
                });

                assertThat(fastLookupCompleted.await(1, TimeUnit.SECONDS))
                        .as("looking up an already-cached key in one zone should not wait for a slow "
                                + "resolution of an unrelated key in a different zone")
                        .isTrue();
                assertThat(fastLookup.get(5, TimeUnit.SECONDS)).isNotNull();

                releaseResolution.countDown();
                assertThat(blockingLookup.get(5, TimeUnit.SECONDS)).isNotNull();
            } finally {
                releaseResolution.countDown();
                executor.shutdownNow();
            }
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    private static TokenPolicy.KeyInformation inlineKey(String signingKey) {
        TokenPolicy.KeyInformation keyInformation = new TokenPolicy.KeyInformation();
        keyInformation.setSigningKey(signingKey);
        return keyInformation;
    }

    private static TokenPolicy.KeyInformation referencedKey(String signingKeyRef) {
        TokenPolicy.KeyInformation keyInformation = new TokenPolicy.KeyInformation();
        keyInformation.setSigningKeyRef(signingKeyRef);
        return keyInformation;
    }

    private static IdentityZone zoneNamed(String zoneId, String keyId, TokenPolicy.KeyInformation keyInformation) {
        IdentityZone zone = new IdentityZone();
        zone.setId(zoneId);
        zone.setName(zoneId);
        zone.setSubdomain(zoneId);

        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeyInformation(Map.of(keyId, keyInformation));
        tokenPolicy.setActiveKeyId(keyId);

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        return zone;
    }

    @Test
    void rejectsAKeyThatIsBothInlineAndReferenced() {
        TokenPolicy.KeyInformation keyInformation = new TokenPolicy.KeyInformation();
        keyInformation.setSigningKey(SIGNING_KEY);
        keyInformation.setSigningKeyRef("also-a-ref");
        configureDefaultZoneKeyInformation(Map.of("ambiguous", keyInformation), "ambiguous");

        assertThatThrownBy(() -> keyInfoService.getKeys())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ambiguous")
                .hasMessageContaining("not both");
    }

    @Test
    void rejectsAKeyThatIsNeitherInlineNorReferenced() {
        // TokenPolicy.setKeyInformation() already rejects an entry that is neither inline nor
        // referenced, so the "empty" KeyInformation used here is injected via reflection to reach
        // KeyInfoService's own resolution-time guard directly.
        TokenPolicy tokenPolicy = new TokenPolicy();
        ReflectionTestUtils.setField(tokenPolicy, "keys", Map.of("empty", new TokenPolicy.KeyInformation()));
        tokenPolicy.setActiveKeyId("empty");
        configureDefaultZoneTokenPolicy(tokenPolicy);

        assertThatThrownBy(() -> keyInfoService.getKeys())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    private void configureDefaultZoneKeys(Map<String, String> keys) {
        IdentityZoneHolder.clear();
        IdentityZoneProvisioning provisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);
        IdentityZone zone = IdentityZone.getUaa();
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(keys);
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(provisioning.retrieve("uaa")).thenReturn(zone);
    }

    private void configureDefaultZoneKeyInformation(Map<String, TokenPolicy.KeyInformation> keys, String activeKeyId) {
        IdentityZoneHolder.clear();
        IdentityZoneProvisioning provisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);
        IdentityZone zone = IdentityZone.getUaa();
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeyInformation(keys);
        tokenPolicy.setActiveKeyId(activeKeyId);
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(provisioning.retrieve("uaa")).thenReturn(zone);
    }

    private void configureDefaultZoneTokenPolicy(TokenPolicy tokenPolicy) {
        IdentityZoneHolder.clear();
        IdentityZoneProvisioning provisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);
        IdentityZone zone = IdentityZone.getUaa();
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(provisioning.retrieve("uaa")).thenReturn(zone);
    }
}
