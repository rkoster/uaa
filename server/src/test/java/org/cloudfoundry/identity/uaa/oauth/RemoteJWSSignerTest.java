package org.cloudfoundry.identity.uaa.oauth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.SigningServiceGrpc;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RemoteJWSSignerTest {

    private FakeSigningService service;
    private RemoteJWSSigner signer;

    @BeforeEach
    void setUp() throws Exception {
        service = new FakeSigningService();
        signer = new RemoteJWSSigner(
                SigningServiceGrpc.newBlockingStub(service.channel()),
                FakeSigningService.KEY_REF,
                "RS256",
                Duration.ofSeconds(2));
    }

    @AfterEach
    void tearDown() throws Exception {
        service.close();
    }

    @Test
    void producesASignatureThatVerifiesAgainstThePublicKey() throws Exception {
        byte[] signingInput = "header.payload".getBytes(StandardCharsets.UTF_8);
        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

        Base64URL result = signer.sign(header, signingInput);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(service.publicKey());
        verifier.update(signingInput);
        assertThat(verifier.verify(result.decode())).isTrue();
        assertThat(service.signCallCount()).isEqualTo(1);
    }

    @Test
    void reportsSupportedAlgorithms() {
        assertThat(signer.supportedJWSAlgorithms()).contains(JWSAlgorithm.RS256);
    }

    @Test
    void translatesATransportFailureIntoAJoseException() {
        service.failWith(io.grpc.Status.UNAVAILABLE);
        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

        assertThatThrownBy(() -> signer.sign(header, "x".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("UNAVAILABLE");
    }
}
