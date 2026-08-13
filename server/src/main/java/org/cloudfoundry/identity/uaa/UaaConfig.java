package org.cloudfoundry.identity.uaa;

import io.grpc.ManagedChannel;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDomainSocketChannel;
import io.netty.channel.unix.DomainSocketAddress;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.LocalPemSigningKeyProvider;
import org.cloudfoundry.identity.uaa.oauth.RemoteSigningChannel;
import org.cloudfoundry.identity.uaa.oauth.RemoteSigningKeyProvider;
import org.cloudfoundry.identity.uaa.oauth.SigningKeyProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for application-wide beans, as well as "infrastructure" beans
 * that help enable other beans (e.g. during the migration from XML config to Java config).
 */
@Configuration
@EnableConfigurationProperties({
        UaaProperties.Uaa.class,
        UaaProperties.Login.class,
        UaaProperties.Logout.class,
        UaaProperties.Servlet.class,
        UaaProperties.RootLevel.class,
        UaaProperties.Csp.class,
        UaaProperties.Metrics.class,
        UaaProperties.Zones.class,
        UaaProperties.GlobalClientSecretPolicy.class,
        UaaProperties.DefaultClientSecretPolicy.class
})
public class UaaConfig {

    @Bean(destroyMethod = "close")
    public KeyInfoService keyInfoService(
            UaaProperties.Uaa uaaProperties,
            @Value("${jwt.token.remote_signer.socket:}") String remoteSignerSocket) {

        List<SigningKeyProvider> providers = new ArrayList<>();
        providers.add(new LocalPemSigningKeyProvider());
        List<AutoCloseable> closeables = new ArrayList<>();

        if (StringUtils.hasText(remoteSignerSocket)) {
            NioEventLoopGroup eventLoopGroup = new NioEventLoopGroup();
            ManagedChannel channel = NettyChannelBuilder
                    .forAddress(new DomainSocketAddress(remoteSignerSocket))
                    .eventLoopGroup(eventLoopGroup)
                    .channelType(NioDomainSocketChannel.class)
                    .usePlaintext()
                    .build();
            // gRPC does not take ownership of an externally supplied event loop group, so nothing
            // shuts down its (non-daemon) threads unless RemoteSigningChannel does so explicitly.
            RemoteSigningChannel remoteSigningChannel = new RemoteSigningChannel(channel, eventLoopGroup);
            providers.add(new RemoteSigningKeyProvider(remoteSigningChannel.channel(), Duration.ofSeconds(2), 5));
            closeables.add(remoteSigningChannel);
        }

        return new KeyInfoService(uaaProperties.url(), List.copyOf(providers), closeables);
    }

}
