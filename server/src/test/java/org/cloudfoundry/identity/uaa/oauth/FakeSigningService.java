package org.cloudfoundry.identity.uaa.oauth;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.GetPublicKeyRequest;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.GetPublicKeyResponse;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.SignRequest;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.SignResponse;
import org.cloudfoundry.identity.uaa.oauth.signer.v1.SigningServiceGrpc;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In-process implementation of the signing service, for tests only.
 *
 * <p>Holds a key pair in memory and signs with it directly. That is precisely
 * what the remote signing feature exists to avoid, so this class must never
 * be packaged or deployed. It exists so the client side can be tested without
 * a socket, a network or an external key store.
 */
public class FakeSigningService extends SigningServiceGrpc.SigningServiceImplBase implements AutoCloseable {

    public static final String KEY_REF = "test-key";

    private final KeyPair keyPair;
    private final Server server;
    private final ManagedChannel channel;
    private final AtomicInteger signCallCount = new AtomicInteger();
    private final AtomicInteger publicKeyCallCount = new AtomicInteger();

    private volatile io.grpc.StatusRuntimeException failWith;

    public FakeSigningService() throws IOException {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        String name = InProcessServerBuilder.generateName();
        this.server = InProcessServerBuilder.forName(name).directExecutor().addService(this).build().start();
        this.channel = InProcessChannelBuilder.forName(name).directExecutor().build();
    }

    public ManagedChannel channel() {
        return channel;
    }

    public int signCallCount() {
        return signCallCount.get();
    }

    public int publicKeyCallCount() {
        return publicKeyCallCount.get();
    }

    /** Makes every subsequent call fail, to exercise error handling. */
    public void failWith(io.grpc.Status status) {
        this.failWith = status.asRuntimeException();
    }

    public void stopFailing() {
        this.failWith = null;
    }

    @Override
    public void getPublicKey(GetPublicKeyRequest request, StreamObserver<GetPublicKeyResponse> observer) {
        publicKeyCallCount.incrementAndGet();
        if (failWith != null) {
            observer.onError(failWith);
            return;
        }
        if (!KEY_REF.equals(request.getKeyRef())) {
            observer.onError(io.grpc.Status.NOT_FOUND
                    .withDescription("unknown key_ref: " + request.getKeyRef()).asRuntimeException());
            return;
        }
        observer.onNext(GetPublicKeyResponse.newBuilder()
                .setPublicKeyDer(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setAlgorithm("RS256")
                .setKeyVersion("v1")
                .build());
        observer.onCompleted();
    }

    @Override
    public void sign(SignRequest request, StreamObserver<SignResponse> observer) {
        signCallCount.incrementAndGet();
        if (failWith != null) {
            observer.onError(failWith);
            return;
        }
        try {
            // The caller sends a digest, so sign it with NONEwithRSA after
            // prefixing the PKCS#1 v1.5 DigestInfo for SHA-256.
            byte[] digestInfoPrefix = new byte[]{
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48,
                    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
            byte[] digest = request.getDigest().toByteArray();
            byte[] toSign = new byte[digestInfoPrefix.length + digest.length];
            System.arraycopy(digestInfoPrefix, 0, toSign, 0, digestInfoPrefix.length);
            System.arraycopy(digest, 0, toSign, digestInfoPrefix.length, digest.length);

            Signature signature = Signature.getInstance("NONEwithRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(toSign);

            observer.onNext(SignResponse.newBuilder()
                    .setSignature(ByteString.copyFrom(signature.sign()))
                    .setKeyVersion("v1")
                    .build());
            observer.onCompleted();
        } catch (Exception e) {
            observer.onError(io.grpc.Status.INTERNAL.withCause(e).asRuntimeException());
        }
    }

    /** Digests input the same way the client is expected to. */
    public static byte[] sha256(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }

    public java.security.PublicKey publicKey() {
        return keyPair.getPublic();
    }

    @Override
    public void close() throws InterruptedException {
        channel.shutdownNow();
        server.shutdownNow();
        server.awaitTermination(5, TimeUnit.SECONDS);
    }
}
