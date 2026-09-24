package org.cloudfoundry.identity.uaa.oauth.token;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@ExtendWith(MockitoExtension.class)
class UaaTokenEndpointTests {

    private UaaTokenEndpoint endpoint;

    @Mock
    private ResponseEntity mockResponseEntity;

    @BeforeEach
    void setup() {
        endpoint = spy(new UaaTokenEndpoint(null, null, null, null, null));
    }

    @Test
    void allowsGetByDefault() throws Exception {
        doReturn(mockResponseEntity).when(endpoint).postAccessToken(any(), any());
        ResponseEntity<OAuth2AccessToken> result = endpoint.doDelegateGet(mock(Principal.class), emptyMap(), new MockHttpServletRequest());
        assertThat(result).isSameAs(mockResponseEntity);
    }

    @Test
    void getIsDisabled() {
        endpoint = spy(new UaaTokenEndpoint(null, null, null, null, false));
        assertThatThrownBy(() -> endpoint.doDelegateGet(mock(Principal.class), emptyMap(), new MockHttpServletRequest())).asInstanceOf(InstanceOfAssertFactories.throwable(HttpRequestMethodNotSupportedException.class));
    }

    @Test
    void postAllowsQueryStringByDefault() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getQueryString()).thenReturn("some-parameter=some-value");
        doReturn(mockResponseEntity).when(endpoint).postAccessToken(any(), any());
        ResponseEntity<OAuth2AccessToken> result = endpoint.doDelegatePost(mock(Principal.class), emptyMap(), request);
        assertThat(result).isSameAs(mockResponseEntity);
    }

    @Test
    void setAllowedRequestMethods() {
        Set<HttpMethod> methods = (Set<HttpMethod>) ReflectionTestUtils.getField(endpoint, "allowedRequestMethods");
        assertThat(methods)
                .containsExactlyInAnyOrder(POST, GET);
    }

    @Test
    void mapsMtlsTokenEndpointAndItsDescendants() throws NoSuchMethodException {
        RequestMapping mapping = UaaTokenEndpoint.class.getAnnotation(RequestMapping.class);

        assertThat(mapping.value())
                .contains("/oauth/mtls/token");
        assertThat(UaaTokenEndpoint.class.getDeclaredMethod("doDelegateGet", Principal.class, Map.class, HttpServletRequest.class)
                .getAnnotation(GetMapping.class).value())
                .containsExactly("**");
        assertThat(UaaTokenEndpoint.class.getDeclaredMethod("doDelegatePost", Principal.class, Map.class,
                HttpServletRequest.class).getAnnotation(PostMapping.class).value())
                .containsExactly("**");
    }

    @Test
    void callToGetAlwaysThrowsSuperMethod() {
        endpoint = new UaaTokenEndpoint(null, null, null, null, false);

        assertThatThrownBy(() -> endpoint.getAccessToken(mock(Principal.class), emptyMap()))
                .isInstanceOf(HttpRequestMethodNotSupportedException.class)
                .satisfies(e -> assertThat(((HttpRequestMethodNotSupportedException) e).getMethod()).isEqualTo("GET"));
    }

    @Test
    void callToGetAlwaysThrowsOverrideMethod() {
        endpoint = new UaaTokenEndpoint(null, null, null, null, false);

        assertThatThrownBy(() -> endpoint.doDelegateGet(mock(Principal.class), emptyMap(), new MockHttpServletRequest()))
                .isInstanceOf(HttpRequestMethodNotSupportedException.class)
                .satisfies(e -> assertThat(((HttpRequestMethodNotSupportedException) e).getMethod()).isEqualTo("GET"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"password", "refresh_token", "authorization_code", "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:saml2-bearer",
            "urn:ietf:params:oauth:grant-type:token-exchange", "user_token", "unknown-grant"})
    void mtlsRejectsOtherGrantsBeforeDelegating(String grantType) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/oauth/mtls/token/alias");
        Map<String, String> parameters = grantType == null ? Map.of() : Map.of("grant_type", grantType);

        assertThatThrownBy(() -> endpoint.doDelegatePost(mock(Principal.class), parameters, request))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessage("the mTLS token endpoint only issues client_credentials tokens");
        assertThatThrownBy(() -> endpoint.doDelegateGet(mock(Principal.class), parameters, request))
                .isInstanceOf(HttpRequestMethodNotSupportedException.class)
                .satisfies(e -> assertThat(((HttpRequestMethodNotSupportedException) e).getSupportedMethods())
                        .containsExactly("POST"));
        verify(endpoint, never()).getAccessToken(any(), any());
        verify(endpoint, never()).postAccessToken(any(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/oauth/mtls/token", "/oauth/mtls/token/alias"})
    void mtlsClientCredentialsStillDelegates(String path) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath(path);
        Map<String, String> parameters = Map.of("grant_type", "client_credentials");
        doReturn(mockResponseEntity).when(endpoint).postAccessToken(any(), any());

        assertThat(endpoint.doDelegatePost(mock(Principal.class), parameters, request)).isSameAs(mockResponseEntity);
        assertThatThrownBy(() -> endpoint.doDelegateGet(mock(Principal.class), parameters, request))
                .isInstanceOf(HttpRequestMethodNotSupportedException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/oauth/token", "/oauth/token/alias/idp"})
    void ordinaryEndpointStillDelegatesUserGrants(String path) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath(path);
        Map<String, String> parameters = Map.of("grant_type", "password");
        doReturn(mockResponseEntity).when(endpoint).postAccessToken(any(), any());

        assertThat(endpoint.doDelegatePost(mock(Principal.class), parameters, request)).isSameAs(mockResponseEntity);
        assertThat(endpoint.doDelegateGet(mock(Principal.class), parameters, request)).isSameAs(mockResponseEntity);
    }
}
