package org.cloudfoundry.identity.uaa.authentication;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.tls.RawPeerCertificateCaptureFilter;
import org.cloudfoundry.identity.uaa.oauth.tls.TlsClientAuthentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.springframework.security.authentication.BadCredentialsException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ClientDetailsAuthenticationProviderTests {

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @Test
    void tlsClientAuthPathIsDetectedAsTlsClientAuth() {
        UaaAuthenticationDetails details = mock(UaaAuthenticationDetails.class);
        when(details.getRequestPath()).thenReturn("/oauth/mtls/token");
        assertThat(ClientDetailsAuthenticationProvider.isTlsClientAuthPath(details)).isTrue();
    }

    @Test
    void tlsClientAuthPathIncludesTokenDescendants() {
        UaaAuthenticationDetails details = mock(UaaAuthenticationDetails.class);
        when(details.getRequestPath()).thenReturn("/oauth/mtls/token/alias");
        assertThat(ClientDetailsAuthenticationProvider.isTlsClientAuthPath(details)).isTrue();
    }

    @Test
    void unrelatedMtlsPathIsNotTlsClientAuth() {
        UaaAuthenticationDetails details = mock(UaaAuthenticationDetails.class);
        when(details.getRequestPath()).thenReturn("/oauth/mtls/not-token");
        assertThat(ClientDetailsAuthenticationProvider.isTlsClientAuthPath(details)).isFalse();
    }

    @Test
    void regularTokenPathIsNotTlsClientAuth() {
        UaaAuthenticationDetails details = mock(UaaAuthenticationDetails.class);
        when(details.getRequestPath()).thenReturn("/oauth/token");
        assertThat(ClientDetailsAuthenticationProvider.isTlsClientAuthPath(details)).isFalse();
    }

    @Test
    void tlsConfigIsReadFromFlatAdditionalInfo() {
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA,
                "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n");

        UaaClient mockClient = mock(UaaClient.class);
        when(mockClient.getAdditionalInformation()).thenReturn(additionalInfo);

        TlsClientAuthConfiguration config =
            ClientDetailsAuthenticationProvider.getTlsClientAuthConfiguration(mockClient);
        assertThat(config).isNotNull();
        assertThat(config.getTrustedCaPem())
            .isEqualTo("-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void readsCompleteTlsConfigurationFromNativeOrJsonValues(boolean jsonEncoded) {
        Object mappings = List.of(Map.of("field", "subject_cn", "claim", "app"));
        Object audiences = List.of("sts.amazonaws.com", "workload/{app}");
        Object requiredClaims = Map.of("app", "test-app");
        UaaClient client = mock(UaaClient.class);
        when(client.getAdditionalInformation()).thenReturn(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem",
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, "proxy-pem",
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "workload/{app}",
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                jsonEncoded ? JsonUtils.writeValueAsString(mappings) : mappings,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                jsonEncoded ? JsonUtils.writeValueAsString(audiences) : audiences,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                jsonEncoded ? JsonUtils.writeValueAsString(requiredClaims) : requiredClaims));
        TlsClientAuthConfiguration expected = new TlsClientAuthConfiguration("ca-pem",
                List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "app")));
        expected.setTrustedProxyCaPem("proxy-pem");
        expected.setSubTemplate("workload/{app}");
        expected.setAudTemplates(List.of("sts.amazonaws.com", "workload/{app}"));
        expected.setRequiredClaims(Map.of("app", "test-app"));

        assertThat(ClientDetailsAuthenticationProvider.getTlsClientAuthConfiguration(client)).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"tls-client-auth-claim-mappings", "tls-client-auth-aud-templates", "tls-client-auth-required-claims"})
    void malformedJsonDoesNotProducePartialConfiguration(String property) {
        UaaClient client = mock(UaaClient.class);
        when(client.getAdditionalInformation()).thenReturn(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem", property, "[invalid"));
        assertThat(ClientDetailsAuthenticationProvider.getTlsClientAuthConfiguration(client)).isNull();
    }

    @Test
    void validateTlsClientAuthPassesClientConfigToCertificateChainLookup() {
        UaaClient uaaClient = mock(UaaClient.class);
        when(uaaClient.getAdditionalInformation()).thenReturn(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem",
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, "proxy-ca-pem"
        ));
        TlsClientAuthentication tlsClientAuthentication = mock(TlsClientAuthentication.class);
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        ClientDetailsAuthenticationProvider provider = new ClientDetailsAuthenticationProvider(
                mock(UserDetailsService.class), mock(PasswordEncoder.class),
                mock(JwtClientAuthentication.class), tlsClientAuthentication);

        provider.validateTlsClientAuth(uaaClient);

        ArgumentCaptor<TlsClientAuthConfiguration> configCaptor =
                ArgumentCaptor.forClass(TlsClientAuthConfiguration.class);
        verify(tlsClientAuthentication).getCertificateChainFromRequest(configCaptor.capture());
        assertThat(configCaptor.getValue().getTrustedProxyCaPem()).isEqualTo("proxy-ca-pem");
    }

    @Test
    void validateTlsClientAuthShortCircuitsWithoutResolvingConfigWhenNoCertificatePresent() {
        UaaClient uaaClient = mock(UaaClient.class);
        TlsClientAuthentication tlsClientAuthentication = mock(TlsClientAuthentication.class);
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(false);
        ClientDetailsAuthenticationProvider provider = new ClientDetailsAuthenticationProvider(
                mock(UserDetailsService.class), mock(PasswordEncoder.class),
                mock(JwtClientAuthentication.class), tlsClientAuthentication);

        assertThatThrownBy(() -> provider.validateTlsClientAuth(uaaClient))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("tls_client_auth: client certificate required");
        verify(uaaClient, never()).getAdditionalInformation();
        verify(tlsClientAuthentication, never()).getCertificateChainFromRequest(any());
    }

    @Test
    void getTlsClientAuthConfigurationReadsTrustedProxyCaFromFlatStringPath() {
        UaaClient uaaClient = mock(UaaClient.class);
        when(uaaClient.getAdditionalInformation()).thenReturn(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem",
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, "proxy-ca-pem"
        ));

        TlsClientAuthConfiguration config =
                ClientDetailsAuthenticationProvider.getTlsClientAuthConfiguration(uaaClient);

        assertThat(config).isNotNull();
        assertThat(config.getTrustedProxyCaPem()).isEqualTo("proxy-ca-pem");
    }

    @Test
    void getTlsClientAuthConfigurationTrustedProxyCaNullWhenAbsent() {
        UaaClient uaaClient = mock(UaaClient.class);
        when(uaaClient.getAdditionalInformation()).thenReturn(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem"
        ));

        TlsClientAuthConfiguration config =
                ClientDetailsAuthenticationProvider.getTlsClientAuthConfiguration(uaaClient);

        assertThat(config).isNotNull();
        assertThat(config.getTrustedProxyCaPem()).isNull();
    }

    @Test
    void getTlsClientAuthConfigurationReadsRequiredClaimsFromFlatStringPath() {
        UaaClient uaaClient = mock(UaaClient.class);
        when(uaaClient.getAdditionalInformation()).thenReturn(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem",
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                        "{\"space_guid\":\"the-expected-space-guid\"}"
        ));

        TlsClientAuthConfiguration config =
                ClientDetailsAuthenticationProvider.getTlsClientAuthConfiguration(uaaClient);

        assertThat(config).isNotNull();
        assertThat(config.getRequiredClaims()).containsEntry("space_guid", "the-expected-space-guid");
    }

    @Test
    void getTlsClientAuthConfigurationRequiredClaimsNullWhenAbsent() {
        UaaClient uaaClient = mock(UaaClient.class);
        when(uaaClient.getAdditionalInformation()).thenReturn(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem"
        ));

        TlsClientAuthConfiguration config =
                ClientDetailsAuthenticationProvider.getTlsClientAuthConfiguration(uaaClient);

        assertThat(config).isNotNull();
        assertThat(config.getRequiredClaims()).isNull();
    }

    @Test
    void validateTlsClientAuthEnforcesRequiredClaimsAgainstAClientSharingTheSameCa() throws Exception {
        // Reproduces the reviewer's impersonation scenario (PR review comment on
        // TlsClientAuthentication.java:150, also flagged at line 175): two UAA clients share the
        // same tls-client-auth-ca (e.g. Diego's shared instance-identity CA). Without a
        // tls-client-auth-required-claims constraint, a certificate for one app could authenticate
        // as ANY client trusting that CA. A client that configures tls-client-auth-required-claims
        // now rejects a certificate belonging to a different space, while an unconstrained client
        // sharing the same CA still accepts it.
        KeyPair caKeyPair = generateKeyPair();
        X500Name caName = new X500Name("CN=Shared Diego Instance Identity CA");
        X509Certificate caCert = signCert(caName, caName, caKeyPair.getPublic(), caKeyPair.getPrivate(), true, BigInteger.ONE);

        KeyPair appKeyPair = generateKeyPair();
        X500Name appSubject = new X500Name("CN=app-instance,OU=space:some-other-space-guid");
        X509Certificate appCert = signCert(appSubject, caName, appKeyPair.getPublic(), caKeyPair.getPrivate(), false, BigInteger.TWO);

        TlsClientAuthentication tlsClientAuthentication = new TlsClientAuthentication();

        MockHttpServletRequest request = new MockHttpServletRequest();
        X509Certificate[] presentedChain = new X509Certificate[]{appCert};
        request.setAttribute("jakarta.servlet.request.X509Certificate", presentedChain);
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE, presentedChain);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            UaaClient unconstrainedClient = mock(UaaClient.class);
            when(unconstrainedClient.getAdditionalInformation()).thenReturn(Map.of(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(caCert)));

            UaaClient constrainedClient = mock(UaaClient.class);
            when(constrainedClient.getAdditionalInformation()).thenReturn(Map.ofEntries(
                    Map.entry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(caCert)),
                    Map.entry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                            List.of(Map.of("field", "subject_ou", "pattern", "^space:(.+)$", "claim", "space_guid"))),
                    Map.entry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                            Map.of("space_guid", "the-expected-space-guid"))));

            ClientDetailsAuthenticationProvider provider = new ClientDetailsAuthenticationProvider(
                    mock(UserDetailsService.class), mock(PasswordEncoder.class),
                    mock(JwtClientAuthentication.class), tlsClientAuthentication);

            assertThat(provider.validateTlsClientAuth(unconstrainedClient))
                    .as("the unconstrained client (no tls-client-auth-required-claims) still accepts any cert from the shared CA")
                    .isTrue();
            assertThatThrownBy(() -> provider.validateTlsClientAuth(constrainedClient))
                    .as("the constrained client rejects a cert whose space_guid doesn't match its required claim")
                    .isInstanceOf(BadCredentialsException.class)
                    .hasMessage("tls_client_auth: certificate does not satisfy required claims");
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate signCert(X500Name subject, X500Name issuer, PublicKey subjectKey,
            PrivateKey signerKey, boolean isCa, BigInteger serial) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 3_600_000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .build(signerKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    private static String toPem(X509Certificate cert) throws Exception {
        java.io.StringWriter sw = new java.io.StringWriter();
        try (org.bouncycastle.util.io.pem.PemWriter pemWriter = new org.bouncycastle.util.io.pem.PemWriter(sw)) {
            pemWriter.writeObject(new org.bouncycastle.util.io.pem.PemObject("CERTIFICATE", cert.getEncoded()));
        }
        return sw.toString();
    }
}
