package egovframework.example.config.security;

import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

public class JwtCookieAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtCookieAuthenticationFilter.class);

    private final JwtDecoder jwtDecoder;
    private final TokenRefreshService refreshService;
    private final CookieUtils cookieUtils;
    private final AuthCookieProperties props;
    private final Converter<Jwt, ? extends AbstractAuthenticationToken> authenticationConverter;

    public JwtCookieAuthenticationFilter(JwtDecoder jwtDecoder,
                                         TokenRefreshService refreshService,
                                         CookieUtils cookieUtils,
                                         AuthCookieProperties props) {
        this.jwtDecoder = jwtDecoder;
        this.refreshService = refreshService;
        this.cookieUtils = cookieUtils;
        this.props = props;

        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("authorities");
        authoritiesConverter.setAuthorityPrefix("");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        converter.setPrincipalClaimName("username");
        this.authenticationConverter = converter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        Optional<String> accessCookie = cookieUtils.readCookie(request, props.getCookie().getAccessTokenName());

        if (accessCookie.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Jwt jwt = jwtDecoder.decode(accessCookie.get());
            authenticate(jwt);
            chain.doFilter(request, response);
            return;
        } catch (JwtException ex) {
            if (isExpiredToken(accessCookie.get())) {
                if (tryRefresh(request, response)) {
                    chain.doFilter(request, response);
                    return;
                }
            } else {
                log.warn("JWT validation failed (likely tampered): {}", ex.getMessage());
            }
            // 변조 또는 refresh 실패: 쿠키 클리어, 인증 비움
            clearAllAuthCookies(response);
            SecurityContextHolder.clearContext();
            chain.doFilter(request, response);
        }
    }

    /**
     * JWT 검증 실패가 "만료"로 인한 것인지 판별한다.
     * NimbusJwtDecoder는 만료를 "Jwt expired at ..." 메시지로 던지지만,
     * iat > exp 인 토큰(테스트용 과거 토큰)은 Nimbus 파싱 단계에서
     * "expiresAt must be after issuedAt" 오류로 먼저 처리된다.
     * 두 경우 모두 실제 exp 가 과거이면 만료로 간주한다.
     */
    private boolean isExpiredToken(String rawToken) {
        try {
            Date exp = JWTParser.parse(rawToken).getJWTClaimsSet().getExpirationTime();
            return exp != null && exp.toInstant().isBefore(Instant.now());
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean tryRefresh(HttpServletRequest request, HttpServletResponse response) {
        Optional<String> refreshCookie = cookieUtils.readCookie(
                request, props.getCookie().getRefreshTokenName());
        if (refreshCookie.isEmpty()) return false;

        Optional<TokenRefreshService.TokenResponse> result = refreshService.refresh(refreshCookie.get());
        if (result.isEmpty()) return false;

        TokenRefreshService.TokenResponse tokens = result.get();
        try {
            Jwt jwt = jwtDecoder.decode(tokens.accessToken());
            authenticate(jwt);

            cookieUtils.writeCookie(response,
                    props.getCookie().getAccessTokenName(),
                    tokens.accessToken(),
                    props.getCookie().getAccessTokenMaxAgeSeconds(),
                    props.getCookie().getSameSiteDefault(),
                    props.getCookie().isSecure());
            if (tokens.refreshToken() != null) {
                cookieUtils.writeCookie(response,
                        props.getCookie().getRefreshTokenName(),
                        tokens.refreshToken(),
                        props.getCookie().getRefreshTokenMaxAgeSeconds(),
                        props.getCookie().getSameSiteStrict(),
                        props.getCookie().isSecure());
            }
            if (tokens.idToken() != null) {
                cookieUtils.writeCookie(response,
                        props.getCookie().getIdTokenName(),
                        tokens.idToken(),
                        props.getCookie().getAccessTokenMaxAgeSeconds(),
                        props.getCookie().getSameSiteStrict(),
                        props.getCookie().isSecure());
            }
            return true;
        } catch (JwtException ex) {
            log.warn("Refreshed JWT failed validation: {}", ex.getMessage());
            return false;
        }
    }

    private void authenticate(Jwt jwt) {
        AbstractAuthenticationToken token = authenticationConverter.convert(jwt);
        SecurityContextHolder.getContext().setAuthentication(token);
    }

    private void clearAllAuthCookies(HttpServletResponse response) {
        cookieUtils.clearCookie(response, props.getCookie().getAccessTokenName(), props.getCookie().isSecure());
        cookieUtils.clearCookie(response, props.getCookie().getRefreshTokenName(), props.getCookie().isSecure());
        cookieUtils.clearCookie(response, props.getCookie().getIdTokenName(), props.getCookie().isSecure());
    }
}
