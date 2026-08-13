package org.cloudfoundry.identity.uaa.oauth;

import io.grpc.ManagedChannel;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.netty.channel.nio.NioEventLoopGroup;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class RemoteSigningChannelTest {

    @Test
    void closeShutsDownBothTheChannelAndItsEventLoopGroup() throws Exception {
        ManagedChannel channel = InProcessChannelBuilder
                .forName("remote-signing-channel-test-" + System.nanoTime())
                .build();
        NioEventLoopGroup eventLoopGroup = new NioEventLoopGroup();

        RemoteSigningChannel remoteSigningChannel = new RemoteSigningChannel(channel, eventLoopGroup);

        assertThat(channel.isShutdown()).isFalse();
        assertThat(eventLoopGroup.isShuttingDown()).isFalse();

        remoteSigningChannel.close();

        assertThat(channel.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        assertThat(channel.isTerminated()).isTrue();
        assertThat(eventLoopGroup.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        assertThat(eventLoopGroup.isTerminated()).isTrue();
    }

    @Test
    void channelReturnsTheWrappedChannel() {
        ManagedChannel channel = InProcessChannelBuilder
                .forName("remote-signing-channel-test-" + System.nanoTime())
                .build();
        NioEventLoopGroup eventLoopGroup = new NioEventLoopGroup();
        RemoteSigningChannel remoteSigningChannel = new RemoteSigningChannel(channel, eventLoopGroup);

        assertThat(remoteSigningChannel.channel()).isSameAs(channel);

        remoteSigningChannel.close();
    }
}
