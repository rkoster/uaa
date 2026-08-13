package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RemoteSigningKeyProviderTest {

    private FakeSigningService service;
    private RemoteSigningKeyProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        service = new FakeSigningService();
        provider = new RemoteSigningKeyProvider(service.channel(), Duration.ofSeconds(2), 3);
    }

    @AfterEach
    void tearDown() throws Exception {
        service.close();
    }

    private static TokenPolicy.KeyInformation keyRef(String ref) {
        TokenPolicy.KeyInformation key = new TokenPolicy.KeyInformation();
        key.setSigningKeyRef(ref);
        return key;
    }

    @Test
    void supportsAKeyReference() {
        assertThat(provider.supports(keyRef("test-key"))).isTrue();
    }

    @Test
    void doesNotSupportAnInlineKey() {
        TokenPolicy.KeyInformation key = new TokenPolicy.KeyInformation();
        key.setSigningKey("-----BEGIN RSA PRIVATE KEY-----");

        assertThat(provider.supports(key)).isFalse();
    }

    @Test
    void resolvesTheReferenceToTheServicesPublicKey() {
        SigningKeyMaterial material = provider.resolve(keyRef(FakeSigningService.KEY_REF), null);

        assertThat(material.algorithm()).isEqualTo("RS256");
        assertThat(material.publicKey()).isEqualTo(service.publicKey());
        assertThat(material.signer()).isInstanceOf(RemoteJWSSigner.class);
        assertThat(service.publicKeyCallCount()).isEqualTo(1);
    }

    @Test
    void rejectsAnUnknownReference() {
        assertThatThrownBy(() -> provider.resolve(keyRef("no-such-key"), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no-such-key");
    }

    @Test
    void retriesWhenTheServiceIsNotYetAvailable() {
        service.failWith(io.grpc.Status.UNAVAILABLE);

        assertThatThrownBy(() -> provider.resolve(keyRef(FakeSigningService.KEY_REF), null))
                .isInstanceOf(IllegalStateException.class);

        assertThat(service.publicKeyCallCount()).isEqualTo(3);
    }
}
