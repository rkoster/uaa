package org.cloudfoundry.identity.uaa.oauth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RemoteSigningEndToEndTest {

    @Test
    void aTokenSignedRemotelyVerifiesAgainstThePublishedJwk() throws Exception {
        try (FakeSigningService service = new FakeSigningService()) {
            RemoteSigningKeyProvider provider =
                    new RemoteSigningKeyProvider(service.channel(), Duration.ofSeconds(2), 3);

            org.cloudfoundry.identity.uaa.zone.TokenPolicy.KeyInformation keyInformation =
                    new org.cloudfoundry.identity.uaa.zone.TokenPolicy.KeyInformation();
            keyInformation.setSigningKeyRef(FakeSigningService.KEY_REF);

            KeyInfo keyInfo = new KeyInfo(
                    "remote-kid",
                    "https://localhost",
                    provider.resolve(keyInformation, null));

            JWSObject jws = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyInfo.keyId()).build(),
                    new Payload(Map.of("sub", "marissa", "iss", "https://localhost")));
            jws.sign(keyInfo.getSigner());

            // Rebuild the public key exactly as /token_keys would publish it.
            Map<String, Object> jwkMap = keyInfo.getJwkMap();
            RSAKey published = RSAKey.parse(Map.of(
                    "kty", jwkMap.get("kty"),
                    "n", jwkMap.get("n"),
                    "e", jwkMap.get("e")));

            assertThat(jws.verify(new RSASSAVerifier(published.toRSAPublicKey()))).isTrue();
            assertThat(service.signCallCount()).isEqualTo(1);
            assertThat(jwkMap).doesNotContainKey("d");
        }
    }

    @Test
    void theJwkMapNeverExposesPrivateMaterial() throws Exception {
        try (FakeSigningService service = new FakeSigningService()) {
            RemoteSigningKeyProvider provider =
                    new RemoteSigningKeyProvider(service.channel(), Duration.ofSeconds(2), 3);
            org.cloudfoundry.identity.uaa.zone.TokenPolicy.KeyInformation keyInformation =
                    new org.cloudfoundry.identity.uaa.zone.TokenPolicy.KeyInformation();
            keyInformation.setSigningKeyRef(FakeSigningService.KEY_REF);

            KeyInfo keyInfo = new KeyInfo("remote-kid", "https://localhost",
                    provider.resolve(keyInformation, null));

            assertThat(keyInfo.getJwkMap().keySet())
                    .doesNotContain("d", "p", "q", "dp", "dq", "qi");
            assertThat(keyInfo.verifierKey()).doesNotContain("PRIVATE");
        }
    }

    @Test
    void keyPublicationSurvivesASigningServiceOutage() throws Exception {
        try (FakeSigningService service = new FakeSigningService()) {
            RemoteSigningKeyProvider provider =
                    new RemoteSigningKeyProvider(service.channel(), Duration.ofSeconds(1), 1);
            org.cloudfoundry.identity.uaa.zone.TokenPolicy.KeyInformation keyInformation =
                    new org.cloudfoundry.identity.uaa.zone.TokenPolicy.KeyInformation();
            keyInformation.setSigningKeyRef(FakeSigningService.KEY_REF);

            KeyInfo keyInfo = new KeyInfo("remote-kid", "https://localhost",
                    provider.resolve(keyInformation, null));

            // The service goes away after the key has been resolved.
            service.failWith(io.grpc.Status.UNAVAILABLE);

            // Publication still works: no call is needed to serve the public key.
            assertThat(keyInfo.getJwkMap()).containsKey("n");
            assertThat(keyInfo.verifierKey()).startsWith("-----BEGIN PUBLIC KEY-----");

            // Signing fails, and reports why.
            JWSObject jws = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    new Payload(Map.of("sub", "marissa")));
            assertThatThrownBy(() -> jws.sign(keyInfo.getSigner()))
                    .hasMessageContaining("UNAVAILABLE");
        }
    }
}
