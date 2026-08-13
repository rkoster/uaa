package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LocalPemSigningKeyProviderTest {

    private static final String RSA_PRIVATE_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXgIBAAKBgQDfTLadf6QgJeS2XXImEHMsa+1O7MmIt44xaL77N2K+J/JGpfV3
            AnkyB06wFZ02sBLB7hko42LIsVEOyTuUBird/3vlyHFKytG7UEt60Fl88SbAEfsU
            JN1i1aSUlunPS/NCz+BKwwKFP9Ss3rNImE9Uc2LMvGy153LHFVW2zrjhTwIDAQAB
            AoGBAJDh21LRcJITRBQ3CUs9PR1DYZPl+tUkE7RnPBMPWpf6ny3LnDp9dllJeHqz
            a3ACSgleDSEEeCGzOt6XHnrqjYCKa42Z+Opnjx/OOpjyX1NAaswRtnb039jwv4gb
            RlwT49Y17UAQpISOo7JFadCBoMG0ix8xr4ScY+zCSoG5v0BhAkEA8llNsiWBJF5r
            LWQ6uimfdU2y1IPlkcGAvjekYDkdkHiRie725Dn4qRiXyABeaqNm2bpnD620Okwr
            sf7LY+BMdwJBAOvgt/ZGwJrMOe/cHhbujtjBK/1CumJ4n2r5V1zPBFfLNXiKnpJ6
            J/sRwmjgg4u3Anu1ENF3YsxYabflBnvOP+kCQCQ8VBCp6OhOMcpErT8+j/gTGQUL
            f5zOiPhoC2zTvWbnkCNGlqXDQTnPUop1+6gILI2rgFNozoTU9MeVaEXTuLsCQQDC
            AGuNpReYucwVGYet+LuITyjs/krp3qfPhhByhtndk4cBA5H0i4ACodKyC6Zl7Tmf
            oYaZoYWi6DzbQQUaIsKxAkEA2rXQjQFsfnSm+w/9067ChWg46p4lq5Na2NpcpFgH
            waZKhM1W0oB8MX78M+0fG3xGUtywTx0D4N7pr1Tk2GTgNw==
            -----END RSA PRIVATE KEY-----""";

    private final LocalPemSigningKeyProvider provider = new LocalPemSigningKeyProvider();

    @Test
    void supportsAKeyWithInlineMaterial() {
        TokenPolicy.KeyInformation key = new TokenPolicy.KeyInformation();
        key.setSigningKey(RSA_PRIVATE_KEY);

        assertThat(provider.supports(key)).isTrue();
    }

    @Test
    void doesNotSupportAKeyReference() {
        TokenPolicy.KeyInformation key = new TokenPolicy.KeyInformation();
        key.setSigningKeyRef("some-ref");

        assertThat(provider.supports(key)).isFalse();
    }

    @Test
    void doesNotSupportASymmetricKey() {
        TokenPolicy.KeyInformation key = new TokenPolicy.KeyInformation();
        key.setSigningKey("testkey");

        assertThat(provider.supports(key)).isFalse();
    }

    @Test
    void resolvesInlineMaterialToASigner() {
        TokenPolicy.KeyInformation key = new TokenPolicy.KeyInformation();
        key.setSigningKey(RSA_PRIVATE_KEY);

        SigningKeyMaterial material = provider.resolve(key, null);

        assertThat(material.algorithm()).isEqualTo("RS256");
        assertThat(material.signer()).isNotNull();
        assertThat(material.publicKey().getAlgorithm()).isEqualTo("RSA");
    }
}
