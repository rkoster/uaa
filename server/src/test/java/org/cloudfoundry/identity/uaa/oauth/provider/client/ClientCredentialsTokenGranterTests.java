package org.cloudfoundry.identity.uaa.oauth.provider.client;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientCredentialsTokenGranterTests {

    private AuthorizationServerTokenServices tokenServices;
    private ClientCredentialsTokenGranter clientCredentialsTokenGranter;
    private ClientDetailsService clientDetailsService;
    private OAuth2RequestFactory requestFactory;
    private TokenRequest tokenRequest;

    @BeforeEach
    void setUp() {
        tokenServices = mock(AuthorizationServerTokenServices.class);
        clientDetailsService = mock(ClientDetailsService.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        tokenRequest = mock(TokenRequest.class);
        clientCredentialsTokenGranter = new ClientCredentialsTokenGranter(tokenServices, clientDetailsService, requestFactory);
    }

    @AfterEach
    void cleanUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void grant() {
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(mock(ClientDetails.class));
        when(requestFactory.createOAuth2Request(any(), any())).thenReturn(oAuth2Request);
        when(tokenServices.createAccessToken(any())).thenReturn(mock(OAuth2AccessToken.class));
        when(oAuth2Request.getAuthorities()).thenReturn(Collections.emptyList());
        assertThat(clientCredentialsTokenGranter.grant(TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS, tokenRequest)).isNotNull();
    }

    @Test
    void grantNoToken() {
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(mock(ClientDetails.class));
        when(requestFactory.createOAuth2Request(any(), any())).thenReturn(oAuth2Request);
        when(tokenServices.createAccessToken(any())).thenReturn(null);
        when(oAuth2Request.getAuthorities()).thenReturn(Collections.emptyList());
        assertThat(clientCredentialsTokenGranter.grant(TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS, tokenRequest)).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {TokenConstants.CLIENT_AUTH_TLS_CLIENT_AUTH,
            TokenConstants.CLIENT_AUTH_PRIVATE_KEY_JWT, TokenConstants.CLIENT_AUTH_SECRET})
    void grantReturnsAccessTokenWithoutRefreshToken(String method) {
        var authentication = new UsernamePasswordAuthenticationToken("client", null, Collections.emptyList());
        UaaAuthenticationDetails details = mock(UaaAuthenticationDetails.class);
        when(details.getAuthenticationMethod()).thenReturn(method);
        authentication.setDetails(details);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        OAuth2Request request = mock(OAuth2Request.class);
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(mock(ClientDetails.class));
        when(requestFactory.createOAuth2Request(any(), any())).thenReturn(request);
        when(request.getAuthorities()).thenReturn(Collections.emptyList());
        DefaultOAuth2AccessToken issued = new DefaultOAuth2AccessToken("access-token");
        issued.setRefreshToken(new DefaultOAuth2RefreshToken("refresh-token"));
        when(tokenServices.createAccessToken(any())).thenReturn(issued);

        OAuth2AccessToken result = clientCredentialsTokenGranter.grant(TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS, tokenRequest);

        assertThat(result).isNotNull();
        assertThat(result.getValue()).isEqualTo("access-token");
        assertThat(result.getRefreshToken()).isNull();
        assertThat(issued.getRefreshToken()).isNotNull();
    }

    @Test
    void grantNoSecretFails() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("username", null, null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        authentication.setDetails(uaaAuthenticationDetails);
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(mock(ClientDetails.class));
        when(requestFactory.createOAuth2Request(any(), any())).thenReturn(oAuth2Request);
        when(tokenServices.createAccessToken(any())).thenReturn(new DefaultOAuth2AccessToken("eyJx"));
        when(oAuth2Request.getAuthorities()).thenReturn(Collections.emptyList());
        when(uaaAuthenticationDetails.getAuthenticationMethod()).thenReturn("none");
        assertThatThrownBy(() -> clientCredentialsTokenGranter
                .grant(TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS, tokenRequest))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("Client credentials required");
    }
}
