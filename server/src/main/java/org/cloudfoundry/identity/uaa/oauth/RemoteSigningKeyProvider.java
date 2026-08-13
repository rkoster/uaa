package org.cloudfoundry.identity.uaa.oauth;

import io.grpc.Channel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.GetPublicKeyRequest;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.GetPublicKeyResponse;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.SigningServiceGrpc;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Resolves keys held in an external key store, named by reference rather than
 * carried inline. The private key never enters this process.
 *
 * <p>The reference is opaque here: the signing service maps it to a
 * backend-specific identifier and rejects references it does not recognise.
 * That keeps the set of usable keys under the operator's control rather than
 * the caller's.
 */
public class RemoteSigningKeyProvider implements SigningKeyProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(RemoteSigningKeyProvider.class);

    private final SigningServiceGrpc.SigningServiceBlockingStub stub;
    private final Duration deadline;
    private final int maxAttempts;

    public RemoteSigningKeyProvider(Channel channel, Duration deadline, int maxAttempts) {
        this.stub = SigningServiceGrpc.newBlockingStub(channel);
        this.deadline = deadline;
        this.maxAttempts = maxAttempts;
    }

    @Override
    public boolean supports(TokenPolicy.KeyInformation key) {
        return !UaaStringUtils.isEmpty(key.getSigningKeyRef());
    }

    @Override
    public SigningKeyMaterial resolve(TokenPolicy.KeyInformation key, String algorithm) {
        String keyRef = key.getSigningKeyRef().trim();
        GetPublicKeyResponse response = fetchPublicKey(keyRef);

        String resolvedAlgorithm = algorithm != null ? algorithm
                : (key.getSigningAlg() != null ? key.getSigningAlg() : response.getAlgorithm());

        return new SigningKeyMaterial(
                new RemoteJWSSigner(stub, keyRef, resolvedAlgorithm, deadline),
                decodePublicKey(response),
                resolvedAlgorithm,
                decodeCertificate(response));
    }

    private GetPublicKeyResponse fetchPublicKey(String keyRef) {
        GetPublicKeyRequest request = GetPublicKeyRequest.newBuilder().setKeyRef(keyRef).build();
        StatusRuntimeException last = null;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return stub.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS)
                        .getPublicKey(request);
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() == Status.Code.NOT_FOUND) {
                    throw new IllegalArgumentException(
                            "Signing service does not know key reference " + keyRef, e);
                }
                last = e;
                LOGGER.warn("Could not fetch public key for {} (attempt {} of {}): {}",
                        keyRef, attempt, maxAttempts, e.getStatus());
                sleepBeforeRetry(attempt);
            }
        }
        throw new IllegalStateException(
                "Signing service unavailable after " + maxAttempts + " attempts for key " + keyRef, last);
    }

    private void sleepBeforeRetry(int attempt) {
        try {
            Thread.sleep(Math.min(1000L * attempt, 5000L));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static PublicKey decodePublicKey(GetPublicKeyResponse response) {
        byte[] der = response.getPublicKeyDer().toByteArray();
        String keyAlgorithm = response.getAlgorithm().startsWith("ES") ? "EC" : "RSA";
        try {
            return KeyFactory.getInstance(keyAlgorithm)
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("Signing service returned an unreadable public key", e);
        }
    }

    private static Optional<X509Certificate> decodeCertificate(GetPublicKeyResponse response) {
        if (response.getCertificateDer().isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of((X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(response.getCertificateDer().newInput()));
        } catch (Exception e) {
            LOGGER.warn("Signing service returned an unreadable certificate; ignoring", e);
            return Optional.empty();
        }
    }
}
