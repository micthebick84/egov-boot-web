package egovframework.example.config.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * RP-initiated logout per OIDC spec:
 * 1. egov 인증 쿠키(access/refresh/id) 모두 Max-Age=0으로 클리어
 * 2. id_token이 존재하면 id_token_hint으로 포함하여
 *    {@code <issuer>/logout?id_token_hint=...&post_logout_redirect_uri=...} 로 302
 * 3. netis-auth가 자체 세션 삭제 후 post_logout_redirect_uri로 다시 302
 */
@Component
public class RpInitiatedLogoutHandler implements LogoutSuccessHandler {

    private final String issuerUri;
    private final CookieUtils cookieUtils;
    private final AuthCookieProperties props;

    public RpInitiatedLogoutHandler(
            @Value("${spring.security.oauth2.client.provider.netis-auth.issuer-uri}") String issuerUri,
            CookieUtils cookieUtils,
            AuthCookieProperties props) {
        this.issuerUri = issuerUri;
        this.cookieUtils = cookieUtils;
        this.props = props;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {

        Optional<String> idToken = cookieUtils.readCookie(request, props.getCookie().getIdTokenName());

        cookieUtils.clearCookie(response, props.getCookie().getAccessTokenName(), props.getCookie().isSecure());
        cookieUtils.clearCookie(response, props.getCookie().getRefreshTokenName(), props.getCookie().isSecure());
        cookieUtils.clearCookie(response, props.getCookie().getIdTokenName(), props.getCookie().isSecure());

        String encodedRedirectUri = UriUtils.encode(props.getPostLogoutRedirectUri(), StandardCharsets.UTF_8);

        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(issuerUri)
                .path("/logout")
                .queryParam("post_logout_redirect_uri", encodedRedirectUri);

        idToken.ifPresent(t -> builder.queryParam("id_token_hint", t));

        response.sendRedirect(builder.build(true).toUriString());
    }
}
