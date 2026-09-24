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
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.tls.RawPeerCertificateCaptureFilter;
import org.cloudfoundry.identity.uaa.oauth.tls.MtlsEndpointAvailabilityFilter;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZoneContextPathSessionFilter;
import org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/** Regression coverage for PR #4076 C5: certificate failures must be OAuth authentication errors. */
@TestPropertySource(properties = {"uaa.mtls-enabled=true", "zones.paths.enabled=true"})
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

    @Autowired
    @Qualifier("mtlsEndpointAvailabilityFilter")
    FilterRegistrationBean<MtlsEndpointAvailabilityFilter> availabilityFilter;

    private static X509Certificate ca;
    private static X509Certificate leaf;
    private static X509Certificate wrongCaLeaf;
    private static X509Certificate expiredLeaf;
    private static String caPem;
    private static String newCaPem;
    private static X509Certificate newLeaf;

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
        caPem = toPem(ca);
        KeyPair newCaKey = generateKeyPair();
        // Reusing a CA subject during key rotation must also work.
        newCaPem = toPem(signCertificate(CA_SUBJECT, CA_SUBJECT, newCaKey, newCaKey, true, 5, 3_600_000));
        newLeaf = signCertificate(leafSubject, CA_SUBJECT, leafKey, newCaKey, false, 6, 3_600_000);
    }

    private static String toPem(X509Certificate certificate) throws Exception {
        StringWriter writer = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
        }
        return writer.toString();
    }

    @BeforeEach
    void includeCertificateCaptureFilter() {
        // MockMvc does not automatically install servlet FilterRegistrationBeans.
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(zonePathFilter.getFilter())
                .addFilter(zoneSessionFilter.getFilter())
                .addFilter(rawPeerFilter.getFilter())
                .addFilter(availabilityFilter.getFilter())
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
    void caRotationAcceptsOverlapAndRejectsRemovedAnchor(ClientIdentification identification) throws Exception {
        String clientId = createMtlsClient(caPem);
        mockMvc.perform(tokenRequest(clientId, identification, leaf)).andExpect(status().isOk());
        mockMvc.perform(tokenRequest(clientId, identification, newLeaf)).andExpect(status().isUnauthorized());

        updateTrustBundle(clientId, caPem + newCaPem);
        assertBoundToken(clientId, identification, leaf);
        assertBoundToken(clientId, identification, newLeaf);
        mockMvc.perform(tokenRequest(clientId, identification, wrongCaLeaf))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));

        updateTrustBundle(clientId, newCaPem);
        mockMvc.perform(tokenRequest(clientId, identification, leaf))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));
        assertBoundToken(clientId, identification, newLeaf);
    }

    private void updateTrustBundle(String clientId, String bundle) throws Exception {
        Map<String, Object> client = Map.of("client_id", clientId,
                "authorized_grant_types", List.of(GRANT_TYPE_CLIENT_CREDENTIALS),
                "scope", List.of("uaa.none"), "authorities", List.of("uaa.resource"),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, bundle);
        mockMvc.perform(put("/oauth/clients/" + clientId).header(AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON).content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isOk());
    }

    private void assertBoundToken(String clientId, ClientIdentification identification, X509Certificate certificate)
            throws Exception {
        var response = mockMvc.perform(tokenRequest(clientId, identification, certificate))
                .andExpect(status().isOk()).andReturn().getResponse();
        var token = JwtHelper.decode((String) JsonUtils.readValueAsMap(response.getContentAsString()).get("access_token"));
        token.verifySignature(keyInfoService.getKey(token.getHeader().getKid()).getVerifier());
        String thumbprint = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        assertThat(JsonUtils.readValueAsMap(token.getClaims()))
                .containsEntry("client_id", clientId).containsEntry("cnf", Map.of("x5t#S256", thumbprint));
    }

    @ParameterizedTest
    @ValueSource(strings = {"tls-client-auth-ca", "tls-client-auth-trusted-proxy-ca"})
    void clientAdminAcceptsTrustBundle(String property) throws Exception {
        Map<String, Object> client = new java.util.HashMap<>(Map.of(
                "client_id", "bundle" + generator.generate(),
                "authorized_grant_types", List.of(GRANT_TYPE_CLIENT_CREDENTIALS),
                "scope", List.of("uaa.none"), "authorities", List.of("uaa.resource"),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, caPem));
        client.put(property, caPem + newCaPem);
        mockMvc.perform(post("/oauth/clients").header(AUTHORIZATION, "Bearer " + adminToken)
                        .accept(APPLICATION_JSON).contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());
        assertThat(clientDetailsService.loadClientByClientId((String) client.get("client_id")).getAdditionalInformation())
                .containsEntry(property, caPem + newCaPem);
    }

    @ParameterizedTest
    @EnumSource(ClientIdentification.class)
    void malformedSecondCertificateRejectsWholeTrustBundle(ClientIdentification identification) throws Exception {
        String bundle = caPem + "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n";
        mockMvc.perform(tokenRequest(createMtlsClient(bundle), identification, leaf))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
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
    @CsvSource({
            "BASIC, /oauth/mtls/token, false", "PARAMETER, /oauth/mtls/token, false",
            "BASIC, /oauth/mtls/token, true", "PARAMETER, /oauth/mtls/token, true",
            "BASIC, /z/default/oauth/mtls/token, false", "PARAMETER, /z/default/oauth/mtls/token, false",
            "BASIC, /oauth/mtls/token/alias, false", "PARAMETER, /z/default/oauth/mtls/token/alias, false"
    })
    void ordinarySecretClientCannotAuthenticateAtMtlsEndpoint(ClientIdentification identification,
            String path, boolean certificatePresent) throws Exception {
        String clientId = "secretclient" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(), Map.of());
        var request = post(path).servletPath(path)
                .accept(APPLICATION_JSON).contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS);
        if (identification == ClientIdentification.BASIC) {
            request.header(AUTHORIZATION, basic(clientId, SECRET));
        } else {
            request.param("client_id", clientId).param("client_secret", SECRET);
        }
        if (certificatePresent) {
            request.requestAttr("jakarta.servlet.request.X509Certificate", new X509Certificate[]{leaf});
        }

        mockMvc.perform(request)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").value(
                        "tls_client_auth: /oauth/mtls/token requires a client configured with tls-client-auth-ca"))
                .andExpect(jsonPath("$.access_token").doesNotExist());

        // Prove the secret itself is valid and remains usable at the ordinary endpoint.
        mockMvc.perform(post("/oauth/token").servletPath("/oauth/token")
                        .header(AUTHORIZATION, basic(clientId, SECRET))
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @ParameterizedTest
    @EnumSource(ClientIdentification.class)
    void mtlsClientWithoutCertificateStillFails(ClientIdentification identification) throws Exception {
        var request = tokenRequest(createMtlsClient(caPem), identification, leaf)
                .requestAttr("jakarta.servlet.request.X509Certificate", new X509Certificate[0]);

        mockMvc.perform(request)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").value("tls_client_auth: client certificate required"));
    }

    @ParameterizedTest
    @EnumSource(ClientIdentification.class)
    void requiredClaimsFailureHasDistinctDescriptionWithoutClaimValues(ClientIdentification identification) throws Exception {
        String clientId = "requiredclaims" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(), Map.of(
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, caPem,
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                        List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "app_id")),
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, Map.of("app_id", "other-workload")));
        clientDetailsService.updateClientSecret(clientId, null);

        mockMvc.perform(tokenRequest(clientId, identification, leaf))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").value("tls_client_auth: certificate does not satisfy required claims"))
                .andExpect(jsonPath("$.access_token").doesNotExist());

        // A trusted certificate becomes acceptable once its required claim matches.
        UaaClientDetails client = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId);
        Map<String, Object> info = new java.util.HashMap<>(client.getAdditionalInformation());
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, Map.of("app_id", "test-workload"));
        client.setAdditionalInformation(info);
        clientDetailsService.updateClientDetails(client);
        assertBoundToken(clientId, identification, leaf);

        // An untrusted certificate must still fail chain validation, before the claim check.
        mockMvc.perform(tokenRequest(clientId, identification, wrongCaLeaf))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error_description").value(
                        "tls_client_auth: certificate chain validation failed: Path does not chain with any of the trust anchors"));
    }

    @Test
    void proxyTrustFailureKeepsGenericCertificateError() throws Exception {
        String clientId = "proxyfailure" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(), Map.of(
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, caPem,
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, caPem));
        clientDetailsService.updateClientSecret(clientId, null);
        // A certificate is present, but a proxy-only client requires trusted XFCC forwarding.
        mockMvc.perform(tokenRequest(clientId, ClientIdentification.PARAMETER, leaf))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error_description").value("tls_client_auth: certificate validation failed"));
    }

    @Test
    void trustedCertificateStillAuthenticatesThroughZonePath() throws Exception {
        String clientId = createMtlsClient(caPem);
        String path = "/z/default/oauth/mtls/token";
        var response = mockMvc.perform(post(path).servletPath(path)
                        .accept(APPLICATION_JSON).contentType(APPLICATION_FORM_URLENCODED)
                        .param("client_id", clientId).param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS)
                        .param("token_format", "jwt")
                        .requestAttr("jakarta.servlet.request.X509Certificate", new X509Certificate[]{leaf}))
                .andExpect(status().isOk()).andReturn().getResponse();
        Map<String, Object> body = JsonUtils.readValueAsMap(response.getContentAsString());
        Map<String, Object> claims = JsonUtils.readValueAsMap(
                JwtHelper.decode((String) body.get("access_token")).getClaims());
        assertThat(claims).containsEntry("client_id", clientId)
                .containsEntry("client_auth_method", "tls_client_auth").containsKey("cnf");
    }

    @ParameterizedTest
    @ValueSource(strings = {"/oauth/mtls/token", "/oauth/mtls/token/alias", "/z/default/oauth/mtls/token",
            "/z/default/oauth/mtls/token/alias"})
    void mtlsGetIsRejectedEvenWithValidCertificate(String path) throws Exception {
        String clientId = createMtlsClient(caPem);
        mockMvc.perform(request(HttpMethod.GET, path).servletPath(path)
                        .accept(APPLICATION_JSON).contentType(APPLICATION_FORM_URLENCODED)
                        .param("client_id", clientId).param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS)
                        .requestAttr("jakarta.servlet.request.X509Certificate", new X509Certificate[]{leaf}))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().string("Allow", "POST"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
        assertBoundToken(clientId, ClientIdentification.PARAMETER, leaf);
    }

    @Test
    void regularEndpointRetainsConfiguredGetSupport() throws Exception {
        String clientId = "getclient" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(), Map.of());
        mockMvc.perform(request(HttpMethod.GET, "/oauth/token").servletPath("/oauth/token")
                        .header(AUTHORIZATION, basic(clientId, SECRET))
                        .queryParam("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS))
                .andExpect(status().isOk()).andExpect(jsonPath("$.access_token").isNotEmpty());
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
    @CsvSource({
            "POST, /oauth/mtls/token, password", "GET, /oauth/mtls/token, password",
            "POST, /z/default/oauth/mtls/token, password", "GET, /z/default/oauth/mtls/token, password",
            "POST, /oauth/mtls/token, refresh_token", "GET, /oauth/mtls/token, refresh_token",
            "POST, /z/default/oauth/mtls/token, refresh_token", "GET, /z/default/oauth/mtls/token, refresh_token"
    })
    void mtlsEndpointRejectsUserGrants(String method, String path, String grantType) throws Exception {
        String username = "mtlsuser" + generator.generate();
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning,
                username, "uaa.user", OriginKeys.UAA, IdentityZone.getUaaZoneId());
        String clientId = "usergrants" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.user", "client_credentials,password,refresh_token",
                false, null, null, -1, IdentityZone.getUaa(), Map.of());

        // Establish valid user credentials, scopes and a real refresh token using the ordinary endpoint.
        var originalResponse = mockMvc.perform(post("/oauth/token").servletPath("/oauth/token")
                        .header(AUTHORIZATION, basic(clientId, SECRET))
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password").param("username", username).param("password", SECRET)
                        .param("scope", "uaa.user"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andReturn().getResponse();
        String refreshToken = (String) JsonUtils.readValueAsMap(originalResponse.getContentAsString()).get("refresh_token");
        mockMvc.perform(post("/oauth/token").servletPath("/oauth/token")
                        .header(AUTHORIZATION, basic(clientId, SECRET)).contentType(APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token").param("refresh_token", refreshToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.access_token").isNotEmpty());

        UaaClientDetails client = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId);
        client.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(caPem, null));
        clientDetailsService.updateClientDetails(client);
        clientDetailsService.updateClientSecret(clientId, null);

        var result = mockMvc.perform(request(HttpMethod.valueOf(method), path).servletPath(path)
                        .contentType(APPLICATION_FORM_URLENCODED).accept(APPLICATION_JSON)
                        .param("client_id", clientId).param("grant_type", grantType)
                        .param("username", username).param("password", SECRET).param("scope", "uaa.user")
                        .param("refresh_token", refreshToken).param("token_format", "jwt")
                        .requestAttr("jakarta.servlet.request.X509Certificate", new X509Certificate[]{leaf}));
        if (method.equals("GET")) {
            result.andExpect(status().isMethodNotAllowed()).andExpect(header().string("Allow", "POST"));
        } else {
            result.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("invalid_grant"))
                    .andExpect(jsonPath("$.error_description").value(
                            "the mTLS token endpoint only issues client_credentials tokens"));
        }
        result.andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void tokenEndpointAuthMethodMetadataDoesNotSelectAuthentication(boolean configureCa) throws Exception {
        String clientId = "metadata" + generator.generate();
        Map<String, Object> client = new java.util.HashMap<>(Map.of(
                "client_id", clientId, "client_secret", SECRET,
                "authorized_grant_types", List.of(GRANT_TYPE_CLIENT_CREDENTIALS),
                "scope", List.of("uaa.none"), "authorities", List.of("uaa.resource"),
                "token-endpoint-auth-method", configureCa ? "client_secret_basic" : "tls_client_auth"));
        if (configureCa) {
            client.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, caPem);
        }
        mockMvc.perform(post("/oauth/clients").header(AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON).content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());
        mockMvc.perform(put("/oauth/clients/" + clientId).header(AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON).content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isOk());
        assertThat(clientDetailsService.loadClientByClientId(clientId).getAdditionalInformation())
                .containsEntry("token-endpoint-auth-method", client.get("token-endpoint-auth-method"));

        var secretRequest = post("/oauth/token").servletPath("/oauth/token")
                .contentType(APPLICATION_FORM_URLENCODED).header(AUTHORIZATION, basic(clientId, SECRET))
                .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS);
        var certificateRequest = tokenRequest(clientId, ClientIdentification.PARAMETER, leaf);
        if (configureCa) {
            mockMvc.perform(secretRequest).andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("invalid_client"));
            mockMvc.perform(certificateRequest).andExpect(status().isOk())
                    .andExpect(jsonPath("$.access_token").isNotEmpty());
        } else {
            mockMvc.perform(secretRequest).andExpect(status().isOk())
                    .andExpect(jsonPath("$.access_token").isNotEmpty());
            mockMvc.perform(certificateRequest).andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error_description").value(
                            "tls_client_auth: /oauth/mtls/token requires a client configured with tls-client-auth-ca"));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"POST", "PUT"})
    void clientAdminRejectsConstantSubjectTemplate(String method) throws Exception {
        String clientId = method.equals("PUT") ? createMtlsClient(caPem) : "constantsub" + generator.generate();
        Map<String, Object> client = Map.of(
                "client_id", clientId, "authorized_grant_types", List.of(GRANT_TYPE_CLIENT_CREDENTIALS),
                "scope", List.of("uaa.none"), "authorities", List.of("uaa.resource"),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, caPem,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "app_id")),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "00000000-0000-0000-0000-000000000000");
        String path = method.equals("POST") ? "/oauth/clients" : "/oauth/clients/" + clientId;
        var response = mockMvc.perform(request(HttpMethod.valueOf(method), path)
                        .header(AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON).accept(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isBadRequest()).andReturn().getResponse();
        assertThat(JsonUtils.readValueAsMap(response.getContentAsString()).get("error_description"))
                .asString().contains("tls-client-auth-sub-template", "placeholder");
    }

    @ParameterizedTest
    @ValueSource(strings = {"00000000-0000-0000-0000-000000000000", "fixed-subject"})
    void invalidStoredConstantSubjectPreventsTokenIssuance(String subject) throws Exception {
        String clientId = "invalidsub" + generator.generate();
        // Deliberately bypass configuration validation to exercise the issuance guard.
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(), Map.of(
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, caPem,
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, subject,
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                        List.of("sts.amazonaws.com", "api://AzureADTokenExchange")));
        clientDetailsService.updateClientSecret(clientId, null);
        mockMvc.perform(tokenRequest(clientId, ClientIdentification.PARAMETER, leaf))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("server_error"))
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist());
    }

    @Test
    void literalAudiencesWorkWithoutSubjectOverride() throws Exception {
        String clientId = "literalaud" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(), Map.of(
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, caPem,
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                        List.of("sts.amazonaws.com", "api://AzureADTokenExchange")));
        clientDetailsService.updateClientSecret(clientId, null);
        var response = mockMvc.perform(tokenRequest(clientId, ClientIdentification.PARAMETER, leaf))
                .andExpect(status().isOk()).andReturn().getResponse();
        Map<String, Object> body = JsonUtils.readValueAsMap(response.getContentAsString());
        var token = JwtHelper.decode((String) body.get("access_token"));
        token.verifySignature(keyInfoService.getKey(token.getHeader().getKid()).getVerifier());
        Map<String, Object> claims = JsonUtils.readValueAsMap(token.getClaims());
        String thumbprint = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded()));
        assertThat(claims).containsEntry("sub", clientId)
                .containsEntry("aud", List.of("sts.amazonaws.com", "api://AzureADTokenExchange"))
                .containsEntry("client_auth_method", "tls_client_auth")
                .containsEntry("cnf", Map.of("x5t#S256", thumbprint));
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
