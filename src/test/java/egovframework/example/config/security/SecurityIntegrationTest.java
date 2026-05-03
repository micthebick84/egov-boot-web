package egovframework.example.config.security;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityIntegrationTest {

    private static WireMockServer wireMock;
    private static String issuerUri;

    @Autowired MockMvc mockMvc;

    @BeforeAll
    static void startWireMock() throws Exception {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        issuerUri = "http://localhost:" + wireMock.port();

        // OIDC discovery endpoint
        wireMock.stubFor(WireMock.get(WireMock.urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(WireMock.okJson(String.format("""
                        {
                          "issuer":"%s",
                          "authorization_endpoint":"%s/oauth2/authorize",
                          "token_endpoint":"%s/oauth2/token",
                          "jwks_uri":"%s/oauth2/jwks",
                          "userinfo_endpoint":"%s/userinfo",
                          "end_session_endpoint":"%s/connect/logout",
                          "id_token_signing_alg_values_supported":["RS256"],
                          "subject_types_supported":["public"],
                          "response_types_supported":["code"]
                        }
                        """, issuerUri, issuerUri, issuerUri, issuerUri, issuerUri, issuerUri))));

        // JWKS — exposes the test public key so JwtDecoder can verify signed JWTs
        String jwksJson = "{\"keys\":[" + TestKeyFactory.rsaKey().toPublicJWK().toJSONString() + "]}";
        wireMock.stubFor(WireMock.get(WireMock.urlEqualTo("/oauth2/jwks"))
                .willReturn(WireMock.okJson(jwksJson)));
    }

    @AfterAll
    static void stopWireMock() {
        if (wireMock != null) wireMock.stop();
    }

    @AfterEach
    void cleanUp() {
        SecurityContextHolder.clearContext();
        if (wireMock != null) {
            wireMock.resetRequests();
        }
    }

    @DynamicPropertySource
    static void registerProps(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.client.registration.netis-auth.client-id", () -> "egov-app");
        registry.add("spring.security.oauth2.client.registration.netis-auth.client-secret", () -> "secret456");
        registry.add("spring.security.oauth2.client.registration.netis-auth.authorization-grant-type",
                () -> "authorization_code");
        registry.add("spring.security.oauth2.client.registration.netis-auth.scope",
                () -> "openid,profile,email");
        registry.add("spring.security.oauth2.client.registration.netis-auth.redirect-uri",
                () -> "{baseUrl}/login/oauth2/code/{registrationId}");
        registry.add("spring.security.oauth2.client.registration.netis-auth.client-authentication-method",
                () -> "client_secret_basic");
        registry.add("spring.security.oauth2.client.provider.netis-auth.issuer-uri", () -> issuerUri);
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> issuerUri);
    }

    @Test
    void unauthenticatedRequestRedirectsToOAuthAuthorization() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/oauth2/authorization/netis-auth"));
    }

    @Test
    void requestWithValidAccessTokenCookieReturns200() throws Exception {
        String jwt = TestKeyFactory.signAccessToken(
                "admin", issuerUri, List.of("ROLE_ADMIN"), Instant.now().plusSeconds(600));

        mockMvc.perform(get("/")
                        .cookie(new jakarta.servlet.http.Cookie("egov_access_token", jwt)))
                .andExpect(status().isOk());
    }

    @Test
    void requestWithExpiredAccessAndValidRefreshIssuesNewCookies() throws Exception {
        String expired = TestKeyFactory.signAccessToken(
                "admin", issuerUri, List.of("ROLE_ADMIN"), Instant.now().minusSeconds(60));
        String fresh = TestKeyFactory.signAccessToken(
                "admin", issuerUri, List.of("ROLE_ADMIN"), Instant.now().plusSeconds(3600));

        wireMock.stubFor(WireMock.post(WireMock.urlEqualTo("/oauth2/token"))
                .withBasicAuth("egov-app", "secret456")
                .withRequestBody(WireMock.containing("grant_type=refresh_token"))
                .willReturn(WireMock.okJson(String.format("""
                        {"access_token":"%s","refresh_token":"new-rt","id_token":"new-it",
                         "expires_in":3600,"token_type":"Bearer"}
                        """, fresh))));

        var result = mockMvc.perform(get("/")
                        .cookie(new jakarta.servlet.http.Cookie("egov_access_token", expired))
                        .cookie(new jakarta.servlet.http.Cookie("egov_refresh_token", "rt-good")))
                .andExpect(status().isOk())
                .andReturn();

        List<String> cookies = result.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        assertThat(cookies).anyMatch(c -> c.contains("egov_access_token=" + fresh));
        assertThat(cookies).anyMatch(c -> c.contains("egov_refresh_token=new-rt"));
        assertThat(cookies).anyMatch(c -> c.contains("egov_id_token=new-it"));

        wireMock.verify(1, com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor(
                com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo("/oauth2/token")));
    }

    @Test
    void csrfDisabledAllowsAuthenticatedPosts() throws Exception {
        // 메인 체인 STATELESS + CSRF 비활성. JWT 쿠키가 인증 경계이며,
        // SameSite=Lax가 cross-site POST를 차단한다. CSRF 토큰 없이도 인증된 POST는 통과.
        String jwt = TestKeyFactory.signAccessToken(
                "admin", issuerUri, List.of("ROLE_ADMIN"), Instant.now().plusSeconds(600));

        mockMvc.perform(post("/addSample.do")
                        .cookie(new jakarta.servlet.http.Cookie("egov_access_token", jwt)))
                .andExpect(status().is2xxSuccessful());
    }

    @Test
    void logoutRedirectsToAuthLogoutAndClearsCookies() throws Exception {
        String jwt = TestKeyFactory.signAccessToken(
                "admin", issuerUri, List.of("ROLE_ADMIN"), Instant.now().plusSeconds(600));

        var result = mockMvc.perform(post("/logout")
                        .cookie(new jakarta.servlet.http.Cookie("egov_access_token", jwt))
                        .cookie(new jakarta.servlet.http.Cookie("egov_id_token", "id-token-xyz"))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirect = result.getResponse().getRedirectedUrl();
        assertThat(redirect).startsWith(issuerUri + "/connect/logout");
        assertThat(redirect).contains("id_token_hint=id-token-xyz");

        List<String> setCookies = result.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        assertThat(setCookies).anyMatch(c -> c.contains("egov_access_token=") && c.contains("Max-Age=0"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_refresh_token=") && c.contains("Max-Age=0"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_id_token=") && c.contains("Max-Age=0"));
    }
}
