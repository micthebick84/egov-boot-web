package egovframework.example.config.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class OAuth2LoginSuccessHandlerTest {

    private OAuth2AuthorizedClientService authorizedClientService;
    private CookieUtils cookieUtils;
    private AuthCookieProperties props;
    private OAuth2LoginSuccessHandler handler;

    @BeforeEach
    void setUp() {
        authorizedClientService = mock(OAuth2AuthorizedClientService.class);
        cookieUtils = new CookieUtils();
        props = new AuthCookieProperties();
        handler = new OAuth2LoginSuccessHandler(authorizedClientService, cookieUtils, props);
    }

    @Test
    void onSuccessWritesAccessRefreshAndIdCookiesAndInvalidatesSession() throws Exception {
        OidcIdToken idToken = OidcIdToken.withTokenValue("id-token-value")
                .subject("admin")
                .claim("sub", "admin")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        OidcUser user = new DefaultOidcUser(List.of(), idToken);
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                user, user.getAuthorities(), "netis-auth");

        ClientRegistration registration = ClientRegistration.withRegistrationId("netis-auth")
                .clientId("egov-app").clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8081/login/oauth2/code/netis-auth")
                .scope(Set.of("openid"))
                .authorizationUri("http://localhost:9000/oauth2/authorize")
                .tokenUri("http://localhost:9000/oauth2/token")
                .build();
        OAuth2AccessToken at = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "access-token-value",
                Instant.now(), Instant.now().plusSeconds(3600));
        OAuth2RefreshToken rt = new OAuth2RefreshToken("refresh-token-value", Instant.now());
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                registration, "admin", at, rt);
        when(authorizedClientService.loadAuthorizedClient("netis-auth", "admin"))
                .thenReturn(authorizedClient);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication);

        List<String> cookies = response.getHeaders("Set-Cookie");
        assertThat(cookies).anySatisfy(c -> assertThat(c).contains("egov_access_token=access-token-value"));
        assertThat(cookies).anySatisfy(c -> assertThat(c).contains("egov_refresh_token=refresh-token-value"));
        assertThat(cookies).anySatisfy(c -> assertThat(c).contains("egov_id_token=id-token-value"));
        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void redirectsToSavedRequestOrRoot() throws Exception {
        OidcIdToken idToken = OidcIdToken.withTokenValue("idt").subject("u")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600)).build();
        OidcUser user = new DefaultOidcUser(List.of(), idToken);
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                user, user.getAuthorities(), "netis-auth");
        ClientRegistration registration = ClientRegistration.withRegistrationId("netis-auth")
                .clientId("egov-app").clientSecret("s")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8081/login/oauth2/code/netis-auth")
                .scope(Set.of("openid")).authorizationUri("http://x").tokenUri("http://x").build();
        OAuth2AccessToken at = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "at", Instant.now(),
                Instant.now().plusSeconds(3600));
        when(authorizedClientService.loadAuthorizedClient(any(), any()))
                .thenReturn(new OAuth2AuthorizedClient(registration, "u", at));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(new MockHttpSession());
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo("/");
    }

    @Test
    void redirectsToSavedRequestUrlWhenPresentEvenAfterSessionInvalidation() throws Exception {
        OidcIdToken idToken = OidcIdToken.withTokenValue("idt").subject("u")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600)).build();
        OidcUser user = new DefaultOidcUser(List.of(), idToken);
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                user, user.getAuthorities(), "netis-auth");
        ClientRegistration registration = ClientRegistration.withRegistrationId("netis-auth")
                .clientId("egov-app").clientSecret("s")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8081/login/oauth2/code/netis-auth")
                .scope(Set.of("openid")).authorizationUri("http://x").tokenUri("http://x").build();
        OAuth2AccessToken at = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "at", Instant.now(),
                Instant.now().plusSeconds(3600));
        when(authorizedClientService.loadAuthorizedClient(any(), any()))
                .thenReturn(new OAuth2AuthorizedClient(registration, "u", at));

        // Simulate a saved request: pre-populate the HttpSessionRequestCache
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/egovSampleList.do");
        request.setRequestURI("/egovSampleList.do");
        request.setServerPort(8081);
        request.setScheme("http");
        request.setServerName("localhost");
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Use the same RequestCache impl as the handler to seed the session
        org.springframework.security.web.savedrequest.HttpSessionRequestCache cache =
                new org.springframework.security.web.savedrequest.HttpSessionRequestCache();
        cache.saveRequest(request, response);

        handler.onAuthenticationSuccess(request, response, authentication);

        // Saved request was /egovSampleList.do — handler must redirect there, NOT to "/"
        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).contains("/egovSampleList.do");
        assertThat(session.isInvalid()).isTrue();
    }
}
