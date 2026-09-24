package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.oauth.tls.MtlsEndpointAvailabilityFilter;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter;
import org.cloudfoundry.identity.uaa.zone.ZoneContextPathSessionFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.config.BeanIds.SPRING_SECURITY_FILTER_CHAIN;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@TestPropertySource(properties = {"uaa.mtls-enabled=false", "zones.paths.enabled=true"})
class MtlsDisabledTokenEndpointMockMvcTests extends AbstractTokenMockMvcTests {

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
    @Qualifier("mtlsEndpointAvailabilityFilter")
    FilterRegistrationBean<MtlsEndpointAvailabilityFilter> availabilityFilter;

    @BeforeEach
    void includeAvailabilityFilter() {
        // MockMvc does not automatically install servlet FilterRegistrationBeans.
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(zonePathFilter.getFilter())
                .addFilter(zoneSessionFilter.getFilter())
                .addFilter(availabilityFilter.getFilter())
                .addFilter(securityFilterChain)
                .build();
    }

    @Test
    void availabilityFilterRunsAfterZoneRewriteAndBeforeSecurity() {
        assertThat(availabilityFilter.isEnabled()).isTrue();
        assertThat(availabilityFilter.getOrder()).isGreaterThan(zonePathFilter.getOrder()).isLessThan(-100);
        // An empty pattern set uses the container-wide default; literal URL patterns miss zone paths.
        assertThat(availabilityFilter.getUrlPatterns()).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /oauth/mtls/token", "POST, /oauth/mtls/token",
            "GET, /oauth/mtls/token/alias", "POST, /oauth/mtls/token/alias",
            "GET, /z/default/oauth/mtls/token", "POST, /z/default/oauth/mtls/token",
            "GET, /z/default/oauth/mtls/token/alias", "POST, /z/default/oauth/mtls/token/alias"
    })
    void disabledEndpointReturnsNotFound(String method, String path) throws Exception {
        mockMvc.perform(request(HttpMethod.valueOf(method), "/uaa" + path)
                        .contextPath("/uaa").servletPath(path)
                        .accept(APPLICATION_JSON).contentType(APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials").param("client_id", "admin"))
                .andExpect(status().isNotFound())
                .andExpect(header().doesNotExist("Location"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
    }

    @Test
    void disabledEndpointRejectsEvenWithCredentialsAndCsrf() throws Exception {
        mockMvc.perform(post("/oauth/mtls/token").servletPath("/oauth/mtls/token")
                        .with(csrf())
                        .header(AUTHORIZATION, basicAdminCredentials())
                        .header("X-Forwarded-Client-Cert", "untrusted-header")
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isNotFound())
                .andExpect(header().doesNotExist("Location"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
    }

    @Test
    void regularTokenEndpointStillWorksWhenMtlsDisabled() throws Exception {
        mockMvc.perform(post("/oauth/token").servletPath("/oauth/token")
                        .header(AUTHORIZATION, basicAdminCredentials())
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    void loginPageStillWorksWhenMtlsDisabled() throws Exception {
        mockMvc.perform(get("/login").servletPath("/login"))
                .andExpect(status().isOk());
    }

    @Test
    void clientMetadataCanBeCreatedAndUpdatedWhenMtlsDisabled() throws Exception {
        String clientId = "metadata" + generator.generate();
        Map<String, Object> client = Map.of(
                "client_id", clientId, "client_secret", SECRET,
                "authorized_grant_types", List.of("client_credentials"),
                "authorities", List.of("uaa.resource"), "scope", List.of("uaa.none"),
                "token-endpoint-auth-method", "tls_client_auth");
        mockMvc.perform(post("/oauth/clients").header(AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON).content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());
        mockMvc.perform(put("/oauth/clients/" + clientId).header(AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON).content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isOk());
        assertThat(clientDetailsService.loadClientByClientId(clientId).getAdditionalInformation())
                .containsEntry("token-endpoint-auth-method", "tls_client_auth");
        // Metadata claiming tls_client_auth does not select it or retire the client's secret.
        mockMvc.perform(post("/oauth/token").servletPath("/oauth/token")
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param("client_id", clientId).param("client_secret", SECRET)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    private static String basicAdminCredentials() {
        return "Basic " + Base64.getEncoder().encodeToString(
                "admin:adminsecret".getBytes(StandardCharsets.UTF_8));
    }
}
