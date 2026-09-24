package org.cloudfoundry.identity.uaa.mock.token;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.tls.RawPeerCertificateCaptureFilter;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZoneContextPathSessionFilter;
import org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.config.BeanIds.SPRING_SECURITY_FILTER_CHAIN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Regression coverage for PR #4076 C5: certificate failures must be OAuth authentication errors. */
@TestPropertySource(properties = "uaa.mtls-enabled=true")
class MtlsClientAuthenticationMockMvcTests extends AbstractTokenMockMvcTests {
    private static final String MTLS_PATH = "/oauth/mtls/token";
    private static final X500Name CA_SUBJECT = new X500Name("CN=Client authentication test CA");

    @Autowired
    @Qualifier(SPRING_SECURITY_FILTER_CHAIN)
    FilterChainProxy securityFilterChain;

    @Autowired
    @Qualifier(ZonePathContextRewritingFilter.REGISTRATION_BEAN_NAME)
    FilterRegistrationBean<ZonePathContextRewritingFilter> zonePathFilter;

    @Autowired
    @Qualifier(ZoneContextPathSessionFilter.REGISTRATION_BEAN_NAME)
    FilterRegistrationBean<ZoneContextPathSessionFilter> zoneSessionFilter;

    @Autowired
    @Qualifier("rawPeerCertificateCaptureFilter")
    FilterRegistrationBean<RawPeerCertificateCaptureFilter> rawPeerFilter;

    private static X509Certificate ca;
    private static X509Certificate leaf;
    private static X509Certificate wrongCaLeaf;
    private static X509Certificate expiredLeaf;
    private static String caPem;

    enum ClientIdentification { PARAMETER, BASIC }

    @BeforeAll
    static void createCertificates() throws Exception {
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
        KeyPair caKey = generateKeyPair();
        KeyPair leafKey = generateKeyPair();
        ca = signCertificate(CA_SUBJECT, CA_SUBJECT, caKey, caKey, true, 1, 3_600_000);
        X500Name leafSubject = new X500Name("CN=test-workload");
        leaf = signCertificate(leafSubject, CA_SUBJECT, leafKey, caKey, false, 2, 3_600_000);
        expiredLeaf = signCertificate(leafSubject, CA_SUBJECT, leafKey, caKey, false, 3, -60_000);
        wrongCaLeaf = signCertificate(leafSubject, new X500Name("CN=Untrusted CA"),
                leafKey, generateKeyPair(), false, 4, 3_600_000);
        StringWriter writer = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", ca.getEncoded()));
        }
        caPem = writer.toString();
    }

    @BeforeEach
    void includeCertificateCaptureFilter() {
        // MockMvc does not automatically install servlet FilterRegistrationBeans.
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(zonePathFilter.getFilter())
                .addFilter(zoneSessionFilter.getFilter())
                .addFilter(rawPeerFilter.getFilter())
                .addFilter(securityFilterChain)
                .build();
    }

    @ParameterizedTest
    @EnumSource(ClientIdentification.class)
    void wrongCaCertificateReturnsInvalidClient(ClientIdentification identification) throws Exception {
        assertCertificateRejected(identification, caPem, wrongCaLeaf,
                "tls_client_auth: certificate chain validation failed: Path does not chain with any of the trust anchors");
    }

    @ParameterizedTest
    @EnumSource(ClientIdentification.class)
    void expiredCertificateReturnsInvalidClient(ClientIdentification identification) throws Exception {
        assertCertificateRejected(identification, caPem, expiredLeaf,
                "tls_client_auth: certificate chain validation failed: validity check failed");
    }

    @ParameterizedTest
    @EnumSource(ClientIdentification.class)
    void caCertificateAsLeafReturnsInvalidClient(ClientIdentification identification) throws Exception {
        assertCertificateRejected(identification, caPem, ca,
                "tls_client_auth: certificate chain validation failed: presented end-entity certificate is itself a CA certificate");
    }

    @ParameterizedTest
    @EnumSource(ClientIdentification.class)
    void malformedStoredCaReturnsInvalidClient(ClientIdentification identification) throws Exception {
        // Direct storage models legacy configuration that bypassed client-admin validation.
        assertCertificateRejected(identification, "not-a-certificate", leaf,
                "tls_client_auth: CA configuration error: No PEM object found in tls-client-auth-ca");
    }

    @ParameterizedTest
    @EnumSource(ClientIdentification.class)
    void trustedCertificateStillIssuesBoundToken(ClientIdentification identification) throws Exception {
        String clientId = createMtlsClient(caPem);
        var response = mockMvc.perform(tokenRequest(clientId, identification, leaf))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andReturn().getResponse();
        Map<String, Object> body = JsonUtils.readValueAsMap(response.getContentAsString());
        Map<String, Object> claims = JsonUtils.readValueAsMap(
                JwtHelper.decode((String) body.get("access_token")).getClaims());
        String thumbprint = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded()));
        assertThat(claims).containsEntry("client_id", clientId)
                .containsEntry("client_auth_method", "tls_client_auth")
                .containsEntry("cnf", Map.of("x5t#S256", thumbprint));
    }

    @Test
    void ordinarySecretClientStillAuthenticatesAtRegularEndpoint() throws Exception {
        String clientId = "secretclient" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(), Map.of());
        mockMvc.perform(post("/oauth/token")
                        .header(AUTHORIZATION, basic(clientId, SECRET))
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"amr", "acr", "amr.method", "acr.level"})
    void clientAdminRejectsReservedClaimMappings(String claim) throws Exception {
        Map<String, Object> client = Map.of(
                "client_id", "reservedclaim" + generator.generate(),
                "authorized_grant_types", List.of(GRANT_TYPE_CLIENT_CREDENTIALS),
                "scope", List.of("uaa.none"), "authorities", List.of("uaa.resource"),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, caPem,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, claim)));

        var response = mockMvc.perform(post("/oauth/clients")
                        .header(AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON).accept(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isBadRequest())
                .andReturn().getResponse();
        assertThat(JsonUtils.readValueAsMap(response.getContentAsString()).get("error_description"))
                .asString().contains("tls-client-auth-claim-mappings", "reserved", claim);
    }

    @ParameterizedTest
    @ValueSource(strings = {"amr", "acr", "amr.method", "acr.level"})
    void persistedMappingsCannotForgeTokenAuthenticationContext(String claim) throws Exception {
        String clientId = "legacyclaims" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(), Map.of(
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, caPem,
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, List.of(
                                new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, claim),
                                new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "cf.app")),
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "workload/{cf.app}",
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES, List.of("federation-audience")));
        clientDetailsService.updateClientSecret(clientId, null);

        var response = mockMvc.perform(tokenRequest(clientId, ClientIdentification.PARAMETER, leaf))
                .andExpect(status().isOk()).andReturn().getResponse();
        Map<String, Object> body = JsonUtils.readValueAsMap(response.getContentAsString());
        var token = JwtHelper.decode((String) body.get("access_token"));
        token.verifySignature(keyInfoService.getKey(token.getHeader().getKid()).getVerifier());
        Map<String, Object> claims = JsonUtils.readValueAsMap(token.getClaims());
        String thumbprint = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded()));
        assertThat(claims).doesNotContainKeys("amr", "acr")
                .containsEntry("client_auth_method", "tls_client_auth")
                .containsEntry("client_id", clientId)
                .containsEntry("sub", "workload/test-workload")
                .containsEntry("cf", Map.of("app", "test-workload"))
                .containsEntry("cnf", Map.of("x5t#S256", thumbprint));
        assertThat(claims.get("aud")).isIn("federation-audience", List.of("federation-audience"));
    }

    private void assertCertificateRejected(ClientIdentification identification, String trustedCa,
            X509Certificate certificate, String description) throws Exception {
        mockMvc.perform(tokenRequest(createMtlsClient(trustedCa), identification, certificate))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").value(description))
                .andExpect(jsonPath("$.access_token").doesNotExist());
    }

    private String createMtlsClient(String trustedCa) {
        String clientId = "mtlsclient" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(),
                Map.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, trustedCa));
        clientDetailsService.updateClientSecret(clientId, null);
        return clientId;
    }

    private MockHttpServletRequestBuilder tokenRequest(String clientId, ClientIdentification identification,
            X509Certificate certificate) {
        var request = post(MTLS_PATH).servletPath(MTLS_PATH)
                .accept(APPLICATION_JSON).contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS).param("token_format", "jwt")
                .requestAttr("jakarta.servlet.request.X509Certificate", new X509Certificate[]{certificate});
        return identification == ClientIdentification.PARAMETER
                ? request.param("client_id", clientId)
                // No client_id parameter: exercise ClientBasicAuthenticationFilter's own error handling.
                : request.header(AUTHORIZATION, basic(clientId, ""));
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate signCertificate(X500Name subject, X500Name issuer, KeyPair subjectKey,
            KeyPair issuerKey, boolean isCa, long serial, long validForMillis) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(serial),
                new Date(System.currentTimeMillis() - 120_000), new Date(System.currentTimeMillis() + validForMillis),
                subject, subjectKey.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        var signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME).build(issuerKey.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }
}
