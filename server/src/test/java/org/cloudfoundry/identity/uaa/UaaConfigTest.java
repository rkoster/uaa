package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.junit.jupiter.api.Test;

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
}
