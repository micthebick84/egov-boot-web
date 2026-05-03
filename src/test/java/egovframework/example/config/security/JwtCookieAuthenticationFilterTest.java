package egovframework.example.config.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class JwtCookieAuthenticationFilterTest {

    private JwtDecoder jwtDecoder;
    private TokenRefreshService refreshService;
    private CookieUtils cookieUtils;
    private AuthCookieProperties props;
    private JwtCookieAuthenticationFilter filter;
    private FilterChain chain;
    private final String issuer = "http://localhost:9000";

    @BeforeEach
    void setUp() throws Exception {
        jwtDecoder = NimbusJwtDecoder.withPublicKey(TestKeyFactory.rsaKey().toRSAPublicKey()).build();
        refreshService = mock(TokenRefreshService.class);
        cookieUtils = new CookieUtils();
        props = new AuthCookieProperties();
        filter = new JwtCookieAuthenticationFilter(jwtDecoder, refreshService, cookieUtils, props);
        chain = mock(FilterChain.class);
        SecurityContextHolder.clearContext();
    }

    @Test
    void noCookieLeavesSecurityContextEmpty() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);
    }

    @Test
    void validJwtSetsAuthentication() throws Exception {
        String jwt = TestKeyFactory.signAccessToken("admin", issuer,
                List.of("ROLE_ADMIN"), Instant.now().plusSeconds(600));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("egov_access_token", jwt));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isInstanceOf(JwtAuthenticationToken.class);
        assertThat(auth.getName()).isEqualTo("admin");
    }

    @Test
    void expiredJwtWithValidRefreshIssuesNewCookiesAndAuthenticates() throws Exception {
        String expiredJwt = TestKeyFactory.signAccessToken("admin", issuer,
                List.of("ROLE_ADMIN"), Instant.now().minusSeconds(60));
        String freshJwt = TestKeyFactory.signAccessToken("admin", issuer,
                List.of("ROLE_ADMIN"), Instant.now().plusSeconds(3600));

        when(refreshService.refresh("rt-good")).thenReturn(Optional.of(
                new TokenRefreshService.TokenResponse(freshJwt, "new-rt", "new-it", 3600, "Bearer")
        ));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(
                new Cookie("egov_access_token", expiredJwt),
                new Cookie("egov_refresh_token", "rt-good"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isInstanceOf(JwtAuthenticationToken.class);
        assertThat(auth.getName()).isEqualTo("admin");

        List<String> setCookies = response.getHeaders("Set-Cookie");
        assertThat(setCookies).anyMatch(c -> c.contains("egov_access_token=" + freshJwt));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_refresh_token=new-rt"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_id_token=new-it"));
    }

    @Test
    void expiredJwtWithFailedRefreshClearsCookiesAndLeavesContextEmpty() throws Exception {
        String expiredJwt = TestKeyFactory.signAccessToken("admin", issuer,
                List.of("ROLE_ADMIN"), Instant.now().minusSeconds(60));
        when(refreshService.refresh("rt-bad")).thenReturn(Optional.empty());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(
                new Cookie("egov_access_token", expiredJwt),
                new Cookie("egov_refresh_token", "rt-bad"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        List<String> setCookies = response.getHeaders("Set-Cookie");
        assertThat(setCookies).anyMatch(c -> c.contains("egov_access_token=") && c.contains("Max-Age=0"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_refresh_token=") && c.contains("Max-Age=0"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_id_token=") && c.contains("Max-Age=0"));
    }

    @Test
    void tamperedJwtClearsCookiesWithoutRefreshAttempt() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(
                new Cookie("egov_access_token", "this.is.not.a.valid.jwt"),
                new Cookie("egov_refresh_token", "rt-still-valid"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(refreshService, never()).refresh(any());
        List<String> setCookies = response.getHeaders("Set-Cookie");
        assertThat(setCookies).anyMatch(c -> c.contains("egov_access_token=") && c.contains("Max-Age=0"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_refresh_token=") && c.contains("Max-Age=0"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_id_token=") && c.contains("Max-Age=0"));
    }

    @Test
    void refreshedJwtSignedByWrongKeyClearsCookies() throws Exception {
        String expiredJwt = TestKeyFactory.signAccessToken("admin", issuer,
                List.of("ROLE_ADMIN"), Instant.now().minusSeconds(60));
        // Simulate auth server returning a token signed by a DIFFERENT key
        com.nimbusds.jose.jwk.RSAKey wrongKey = new com.nimbusds.jose.jwk.gen.RSAKeyGenerator(2048)
                .keyID("wrong-key").generate();
        com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .subject("admin").issuer(issuer).audience("egov-app")
                .issueTime(java.util.Date.from(Instant.now()))
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(3600)))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("username", "admin").claim("authorities", List.of("ROLE_ADMIN"))
                .build();
        com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
                com.nimbusds.jose.JWSAlgorithm.RS256)
                .type(com.nimbusds.jose.JOSEObjectType.JWT)
                .keyID(wrongKey.getKeyID()).build();
        com.nimbusds.jwt.SignedJWT wrongSignedJwt = new com.nimbusds.jwt.SignedJWT(header, claims);
        wrongSignedJwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(wrongKey));
        String wrongKeyJwt = wrongSignedJwt.serialize();

        when(refreshService.refresh("rt-good")).thenReturn(Optional.of(
                new TokenRefreshService.TokenResponse(wrongKeyJwt, "new-rt", "new-it", 3600, "Bearer")
        ));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(
                new Cookie("egov_access_token", expiredJwt),
                new Cookie("egov_refresh_token", "rt-good"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        List<String> setCookies = response.getHeaders("Set-Cookie");
        assertThat(setCookies).anyMatch(c -> c.contains("egov_access_token=") && c.contains("Max-Age=0"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_refresh_token=") && c.contains("Max-Age=0"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_id_token=") && c.contains("Max-Age=0"));
    }

    @Test
    void structurallyValidButForgedJwtClearsCookiesWithoutRefreshAttempt() throws Exception {
        // Token signed by a different key with future exp — JwtDecoder fails, isExpiredToken should say NOT expired
        com.nimbusds.jose.jwk.RSAKey forgedKey = new com.nimbusds.jose.jwk.gen.RSAKeyGenerator(2048)
                .keyID("forged-key").generate();
        com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .subject("admin").issuer(issuer).audience("egov-app")
                .issueTime(java.util.Date.from(Instant.now()))
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(3600))) // future
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("username", "admin").claim("authorities", List.of("ROLE_ADMIN"))
                .build();
        com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
                com.nimbusds.jose.JWSAlgorithm.RS256)
                .type(com.nimbusds.jose.JOSEObjectType.JWT)
                .keyID(forgedKey.getKeyID()).build();
        com.nimbusds.jwt.SignedJWT forgedJwt = new com.nimbusds.jwt.SignedJWT(header, claims);
        forgedJwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(forgedKey));
        String forgedToken = forgedJwt.serialize();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(
                new Cookie("egov_access_token", forgedToken),
                new Cookie("egov_refresh_token", "rt-still-valid"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(refreshService, never()).refresh(any());
        List<String> setCookies = response.getHeaders("Set-Cookie");
        assertThat(setCookies).anyMatch(c -> c.contains("egov_access_token=") && c.contains("Max-Age=0"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_refresh_token=") && c.contains("Max-Age=0"));
        assertThat(setCookies).anyMatch(c -> c.contains("egov_id_token=") && c.contains("Max-Age=0"));
    }
}
