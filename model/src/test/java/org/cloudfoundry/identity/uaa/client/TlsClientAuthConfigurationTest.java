package org.cloudfoundry.identity.uaa.client;

import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class TlsClientAuthConfigurationTest {

    private static final String EXAMPLE_CA = "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n";

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void factoryParsesCompleteNativeOrJsonConfiguration(boolean jsonEncoded) {
        Object mappings = List.of(Map.of("field", "subject_ou", "pattern", "^app:(.+)$", "claim", "cf.app"));
        Object audiences = List.of("sts.amazonaws.com", "workload/{cf.app}");
        Object required = Map.of("cf.app", "app-guid");
        Map<String, Object> info = Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, EXAMPLE_CA,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                jsonEncoded ? JsonUtils.writeValueAsString(mappings) : mappings,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                jsonEncoded ? JsonUtils.writeValueAsString(audiences) : audiences,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                jsonEncoded ? JsonUtils.writeValueAsString(required) : required,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "workload/{cf.app}",
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, "proxy-pem");
        TlsClientAuthConfiguration expected = new TlsClientAuthConfiguration(EXAMPLE_CA,
                List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "cf.app")));
        expected.setSubTemplate("workload/{cf.app}");
        expected.setAudTemplates(List.of("sts.amazonaws.com", "workload/{cf.app}"));
        expected.setRequiredClaims(Map.of("cf.app", "app-guid"));
        expected.setTrustedProxyCaPem("proxy-pem");

        assertThat(TlsClientAuthConfiguration.fromAdditionalInformation(info)).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"tls-client-auth-claim-mappings", "tls-client-auth-aud-templates", "tls-client-auth-required-claims"})
    void factoryReturnsNoPartialConfigurationForMalformedJson(String property) {
        assertThat(TlsClientAuthConfiguration.fromAdditionalInformation(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, EXAMPLE_CA, property, "[invalid"))).isNull();
    }

    @Test
    void factoryRequiresFlatCaStringAndNormalizesBlankOptionalStrings() {
        assertThat(TlsClientAuthConfiguration.fromAdditionalInformation(null)).isNull();
        assertThat(TlsClientAuthConfiguration.fromAdditionalInformation(Map.of())).isNull();
        assertThat(TlsClientAuthConfiguration.fromAdditionalInformation(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, Map.of("ca", EXAMPLE_CA)))).isNull();
        var config = TlsClientAuthConfiguration.fromAdditionalInformation(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, EXAMPLE_CA,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "   ",
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, "\t"));
        assertThat(config).isEqualTo(new TlsClientAuthConfiguration(EXAMPLE_CA, null));
    }

    @Test
    void roundTripsViaJson() throws Exception {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(
            EXAMPLE_CA,
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid"))
        );

        JsonMapper mapper = new JsonMapper();
        String json = mapper.writeValueAsString(config);
        TlsClientAuthConfiguration deserialized = mapper.readValue(json, TlsClientAuthConfiguration.class);

        assertThat(deserialized.getTrustedCaPem()).isEqualTo(EXAMPLE_CA);
        assertThat(deserialized.getClaimMappings()).hasSize(1);
        assertThat(deserialized.getClaimMappings().get(0).getClaim()).isEqualTo("app_guid");
    }

    @Test
    void nullCaMeansNotConfigured() {
        assertThat(TlsClientAuthConfiguration.isConfigured(null)).isFalse();
        assertThat(TlsClientAuthConfiguration.isConfigured(new TlsClientAuthConfiguration(null, null))).isFalse();
    }

    @Test
    void nonNullCaMeansConfigured() {
        assertThat(TlsClientAuthConfiguration.isConfigured(
            new TlsClientAuthConfiguration(EXAMPLE_CA, null))).isTrue();
    }

    @Test
    void claimMappingWithoutPatternUsesFieldDirectly() {
        TlsClientAuthConfiguration.ClaimMapping mapping =
            new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "instance_guid");
        assertThat(mapping.getPattern()).isNull();
        assertThat(mapping.getClaim()).isEqualTo("instance_guid");
    }

    @Test
    void equalConfigurations() {
        TlsClientAuthConfiguration a = new TlsClientAuthConfiguration(
            EXAMPLE_CA,
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid"))
        );
        TlsClientAuthConfiguration b = new TlsClientAuthConfiguration(
            EXAMPLE_CA,
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid"))
        );
        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    void unequalWhenCaDiffers() {
        TlsClientAuthConfiguration a = new TlsClientAuthConfiguration("ca-a", null);
        TlsClientAuthConfiguration b = new TlsClientAuthConfiguration("ca-b", null);
        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void subTemplateRoundTripsViaJson() throws Exception {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(
            EXAMPLE_CA,
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "cf_instance_guid"))
        );
        config.setSubTemplate("o/{cf.org}/s/{cf.space}/a/{cf.app}");

        JsonMapper mapper = new JsonMapper();
        String json = mapper.writeValueAsString(config);
        TlsClientAuthConfiguration deserialized = mapper.readValue(json, TlsClientAuthConfiguration.class);

        assertThat(deserialized.getSubTemplate()).isEqualTo("o/{cf.org}/s/{cf.space}/a/{cf.app}");
    }

    @Test
    void audTemplatesRoundTripsViaJson() throws Exception {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        config.setAudTemplates(List.of(
            "o/{cf.org}/s/{cf.space}/a/{cf.app}",
            "o/{cf.org}/s/{cf.space}",
            "o/{cf.org}"
        ));

        JsonMapper mapper = new JsonMapper();
        String json = mapper.writeValueAsString(config);
        TlsClientAuthConfiguration deserialized = mapper.readValue(json, TlsClientAuthConfiguration.class);

        assertThat(deserialized.getAudTemplates()).containsExactly(
            "o/{cf.org}/s/{cf.space}/a/{cf.app}",
            "o/{cf.org}/s/{cf.space}",
            "o/{cf.org}"
        );
    }

    @Test
    void nullSubTemplateAndAudTemplatesOmittedFromJson() throws Exception {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        // subTemplate and audTemplates left null

        JsonMapper mapper = new JsonMapper();
        String json = mapper.writeValueAsString(config);

        assertThat(json).doesNotContain("tls-client-auth-sub-template");
        assertThat(json).doesNotContain("tls-client-auth-aud-templates");
    }

    @Test
    void equalityIncludesSubTemplateAndAudTemplates() {
        TlsClientAuthConfiguration a = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        a.setSubTemplate("o/{cf.org}");
        a.setAudTemplates(List.of("o/{cf.org}"));

        TlsClientAuthConfiguration b = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        b.setSubTemplate("o/{cf.org}");
        b.setAudTemplates(List.of("o/{cf.org}"));

        TlsClientAuthConfiguration c = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        c.setSubTemplate("different");

        TlsClientAuthConfiguration d = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        d.setSubTemplate("o/{cf.org}");   // same as a
        // d.audTemplates left null        // differs from a

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
        assertThat(a).isNotEqualTo(c);
        assertThat(a).isNotEqualTo(d);
    }

    @Test
    void trustedProxyCaPemRoundTripsViaJson() throws Exception {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        config.setTrustedProxyCaPem("-----BEGIN CERTIFICATE-----\nPROXY\n-----END CERTIFICATE-----\n");

        JsonMapper mapper = new JsonMapper();
        String json = mapper.writeValueAsString(config);
        TlsClientAuthConfiguration deserialized = mapper.readValue(json, TlsClientAuthConfiguration.class);

        assertThat(deserialized.getTrustedProxyCaPem())
                .isEqualTo("-----BEGIN CERTIFICATE-----\nPROXY\n-----END CERTIFICATE-----\n");
        assertThat(json).contains("tls-client-auth-trusted-proxy-ca");
    }

    @Test
    void unequalWhenTrustedProxyCaPemDiffers() {
        TlsClientAuthConfiguration config1 = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        config1.setTrustedProxyCaPem("proxy-ca-1");
        TlsClientAuthConfiguration config2 = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        config2.setTrustedProxyCaPem("proxy-ca-2");

        assertThat(config1).isNotEqualTo(config2);
    }

    @Test
    void requiredClaimsRoundTripsViaJson() throws Exception {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        config.setRequiredClaims(Map.of("space_guid", "the-expected-space-guid"));

        JsonMapper mapper = new JsonMapper();
        String json = mapper.writeValueAsString(config);
        TlsClientAuthConfiguration deserialized = mapper.readValue(json, TlsClientAuthConfiguration.class);

        assertThat(deserialized.getRequiredClaims()).containsEntry("space_guid", "the-expected-space-guid");
        assertThat(json).contains("tls-client-auth-required-claims");
    }

    @Test
    void unequalWhenRequiredClaimsDiffer() {
        TlsClientAuthConfiguration config1 = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        config1.setRequiredClaims(Map.of("space_guid", "space-a"));
        TlsClientAuthConfiguration config2 = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        config2.setRequiredClaims(Map.of("space_guid", "space-b"));

        assertThat(config1).isNotEqualTo(config2);
    }
}
