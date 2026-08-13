package org.cloudfoundry.identity.uaa;

import io.grpc.ManagedChannel;
import io.netty.channel.EventLoopGroup;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.RemoteSigningChannel;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class UaaConfigTest {

    @Test
    void buildsAKeyInfoServiceWithoutARemoteSignerWhenNoSocketIsConfigured() {
        UaaConfig config = new UaaConfig();

        KeyInfoService service = config.keyInfoService(
                new UaaProperties.Uaa("https://localhost"),
                null);

        assertThat(service).isNotNull();
    }

    @Test
    void closingTheKeyInfoServiceShutsDownTheRemoteSignerChannelAndItsEventLoopGroup() throws Exception {
        UaaConfig config = new UaaConfig();
        String socketPath = "/tmp/uaa-config-test-" + UUID.randomUUID() + ".sock";

        KeyInfoService service = config.keyInfoService(new UaaProperties.Uaa("https://localhost"), socketPath);

        List<?> closeables = (List<?>) ReflectionTestUtils.getField(service, "closeables");
        assertThat(closeables).hasSize(1);
        RemoteSigningChannel remoteSigningChannel = (RemoteSigningChannel) closeables.get(0);

        ManagedChannel channel = remoteSigningChannel.channel();
        EventLoopGroup eventLoopGroup =
                (EventLoopGroup) ReflectionTestUtils.getField(remoteSigningChannel, "eventLoopGroup");

        service.close();

        assertThat(channel.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        assertThat(eventLoopGroup.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        assertThat(eventLoopGroup.isTerminated()).isTrue();
    }
}
