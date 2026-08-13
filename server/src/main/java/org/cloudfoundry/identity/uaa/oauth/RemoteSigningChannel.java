package org.cloudfoundry.identity.uaa.oauth;

import io.grpc.ManagedChannel;
import io.netty.channel.EventLoopGroup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

/**
 * Owns a gRPC channel to the remote signing service together with the event
 * loop group it was built with.
 *
 * <p>gRPC does not take ownership of an externally supplied {@link EventLoopGroup}, so nothing
 * shuts down its (non-daemon) threads unless something does so explicitly. Bundling the channel
 * and its event loop group together lets both be shut down as a single unit, e.g. via
 * {@code @Bean(destroyMethod = "close")} when a Spring application context closes.
 */
public class RemoteSigningChannel implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(RemoteSigningChannel.class);
    private static final long SHUTDOWN_TIMEOUT_SECONDS = 5;

    private final ManagedChannel channel;
    private final EventLoopGroup eventLoopGroup;

    public RemoteSigningChannel(ManagedChannel channel, EventLoopGroup eventLoopGroup) {
        this.channel = channel;
        this.eventLoopGroup = eventLoopGroup;
    }

    public ManagedChannel channel() {
        return channel;
    }

    @Override
    public void close() {
        try {
            channel.shutdown();
            if (!channel.awaitTermination(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                channel.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            channel.shutdownNow();
        } finally {
            eventLoopGroup.shutdownGracefully(0, SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }
        LOGGER.info("Shut down remote signing channel and its event loop group");
    }
}
