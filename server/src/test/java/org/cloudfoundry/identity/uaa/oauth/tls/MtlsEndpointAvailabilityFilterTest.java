package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.FilterChain;
import org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class MtlsEndpointAvailabilityFilterTest {
    @ParameterizedTest
    @ValueSource(strings = {"/oauth/mtls/token", "/oauth/mtls/token/", "/oauth/mtls/token/alias",
            "/z/default/oauth/mtls/token", "/z/tenant/oauth/mtls/token/alias"})
    void disabledEndpointStopsTheChainAfterZoneRewriting(String path) throws Exception {
        MockHttpServletRequest request = request(path);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain downstream = mock(FilterChain.class);
        var filter = new MtlsEndpointAvailabilityFilter(false);

        new ZonePathContextRewritingFilter(true).doFilter(request, response,
                (rewritten, wrappedResponse) -> filter.doFilter(rewritten, wrappedResponse, downstream));

        assertThat(response.getStatus()).isEqualTo(404);
        verifyNoInteractions(downstream);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/oauth/token", "/oauth/token/alias/idp", "/login", "/oauth/mtls/tokenize",
            "/oauth/mtls/not-token", ""})
    void disabledFeaturePassesUnrelatedPaths(String path) throws Exception {
        MockHttpServletRequest request = request(path);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain downstream = mock(FilterChain.class);

        new MtlsEndpointAvailabilityFilter(false).doFilter(request, response, downstream);

        verify(downstream).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/oauth/mtls/token", "/oauth/mtls/token/alias", "/oauth/token", "/login"})
    void enabledFeaturePassesAllPaths(String path) throws Exception {
        MockHttpServletRequest request = request(path);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain downstream = mock(FilterChain.class);

        new MtlsEndpointAvailabilityFilter(true).doFilter(request, response, downstream);

        verify(downstream).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    private MockHttpServletRequest request(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/uaa" + path);
        request.setContextPath("/uaa");
        request.setServletPath(path);
        return request;
    }
}
