package org.cloudfoundry.identity.uaa.oauth;

import com.google.protobuf.ByteString;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import io.grpc.StatusRuntimeException;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.SignRequest;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.SignResponse;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.SigningServiceGrpc;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * A {@link JWSSigner} that delegates the signing operation to an external
 * signing service, so the private key is never present in this process.
 *
 * <p>Only a digest crosses the boundary, never the signing input, so no token
 * claims leave the process. The service returns bytes already in JWS wire
 * form, so no cryptographic transformation happens here.
 */
public class RemoteJWSSigner implements JWSSigner {

    private static final Set<JWSAlgorithm> SUPPORTED = Set.of(
            JWSAlgorithm.RS256, JWSAlgorithm.PS256, JWSAlgorithm.ES256, JWSAlgorithm.ES384);

    private final SigningServiceGrpc.SigningServiceBlockingStub stub;
    private final String keyRef;
    private final String algorithm;
    private final Duration deadline;
    private final JCAContext jcaContext = new JCAContext();

    public RemoteJWSSigner(SigningServiceGrpc.SigningServiceBlockingStub stub,
                           String keyRef,
                           String algorithm,
                           Duration deadline) {
        this.stub = stub;
        this.keyRef = keyRef;
        this.algorithm = algorithm;
        this.deadline = deadline;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        byte[] digest = digest(signingInput, header.getAlgorithm());
        try {
            SignResponse response = stub
                    .withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS)
                    .sign(SignRequest.newBuilder()
                            .setKeyRef(keyRef)
                            .setDigest(ByteString.copyFrom(digest))
                            .setAlgorithm(algorithm)
                            .build());
            return Base64URL.encode(response.getSignature().toByteArray());
        } catch (StatusRuntimeException e) {
            throw new JOSEException(
                    "Remote signing failed for key " + keyRef + ": " + e.getStatus(), e);
        }
    }

    private static byte[] digest(byte[] signingInput, JWSAlgorithm alg) throws JOSEException {
        String hash = switch (alg.getName()) {
            case "RS256", "PS256", "ES256" -> "SHA-256";
            case "ES384" -> "SHA-384";
            default -> throw new JOSEException("Unsupported algorithm for remote signing: " + alg);
        };
        try {
            return MessageDigest.getInstance(hash).digest(signingInput);
        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException("No such digest algorithm: " + hash, e);
        }
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return SUPPORTED;
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }
}
