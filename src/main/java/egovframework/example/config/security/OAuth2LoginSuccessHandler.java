package egovframework.example.config.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * OAuth2 핸드셰이크 성공 후:
 * 1. RequestCache에서 saved request URL을 세션 무효화 전에 추출
 * 2. access/refresh/id 토큰을 HttpOnly 쿠키로 직렬화
 * 3. 세션 무효화 (이후 stateless 모드)
 * 4. 부모의 RedirectStrategy로 redirect (URL 검증 + CR/LF 보호 등)
 *
 * SavedRequestAwareAuthenticationSuccessHandler를 상속함으로써:
 * - RequestCache를 setRequestCache(...)로 외부에서 주입 가능 (I1 해결)
 * - getRedirectStrategy().sendRedirect(...)로 URL 검증 가드 유지 (I2 해결)
 *
 * determineTargetUrl(request, response, authentication)은 saved request를 확인하지 않으므로
 * saved request 해석은 직접 requestCache.getRequest(...)로 처리한다.
 */
@Component
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final CookieUtils cookieUtils;
    private final AuthCookieProperties props;

    public OAuth2LoginSuccessHandler(OAuth2AuthorizedClientService authorizedClientService,
                                     CookieUtils cookieUtils,
                                     AuthCookieProperties props) {
        this.authorizedClientService = authorizedClientService;
        this.cookieUtils = cookieUtils;
        this.props = props;
        setDefaultTargetUrl("/");
    }

    /**
     * SecurityConfig 또는 테스트에서 RequestCache 인스턴스를 주입할 수 있다.
     * 부모 클래스의 동일 메서드를 오버라이드하여 this.requestCache와 동기화한다.
     */
    @Override
    public void setRequestCache(RequestCache requestCache) {
        super.setRequestCache(requestCache);
        this.requestCache = requestCache;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        // 1) Saved request URL 추출 (세션 무효화 전에)
        //    determineTargetUrl은 saved request를 확인하지 않으므로 직접 처리한다.
        String targetUrl = getDefaultTargetUrl();
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            String targetUrlParameter = getTargetUrlParameter();
            if (!isAlwaysUseDefaultTargetUrl()
                    && (targetUrlParameter == null
                        || !org.springframework.util.StringUtils.hasText(
                                request.getParameter(targetUrlParameter)))) {
                targetUrl = savedRequest.getRedirectUrl();
                requestCache.removeRequest(request, response);
            }
        } else if (!isAlwaysUseDefaultTargetUrl()) {
            String targetUrlParameter = getTargetUrlParameter();
            if (targetUrlParameter != null) {
                String param = request.getParameter(targetUrlParameter);
                if (org.springframework.util.StringUtils.hasText(param)) {
                    targetUrl = param;
                }
            }
        }
        clearAuthenticationAttributes(request);

        // 2) 토큰을 쿠키로 직렬화
        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            String registrationId = oauthToken.getAuthorizedClientRegistrationId();
            String principalName = oauthToken.getName();
            OAuth2AuthorizedClient client = authorizedClientService
                    .loadAuthorizedClient(registrationId, principalName);

            if (client != null && client.getAccessToken() != null) {
                cookieUtils.writeCookie(response,
                        props.getCookie().getAccessTokenName(),
                        client.getAccessToken().getTokenValue(),
                        props.getCookie().getAccessTokenMaxAgeSeconds(),
                        props.getCookie().getSameSiteDefault(),
                        props.getCookie().isSecure());

                OAuth2RefreshToken refresh = client.getRefreshToken();
                if (refresh != null) {
                    cookieUtils.writeCookie(response,
                            props.getCookie().getRefreshTokenName(),
                            refresh.getTokenValue(),
                            props.getCookie().getRefreshTokenMaxAgeSeconds(),
                            props.getCookie().getSameSiteStrict(),
                            props.getCookie().isSecure());
                }
            }

            if (oauthToken.getPrincipal() instanceof OidcUser oidcUser) {
                cookieUtils.writeCookie(response,
                        props.getCookie().getIdTokenName(),
                        oidcUser.getIdToken().getTokenValue(),
                        props.getCookie().getAccessTokenMaxAgeSeconds(),
                        props.getCookie().getSameSiteStrict(),
                        props.getCookie().isSecure());
            }
        }

        // 3) 세션 무효화 (handshake 끝, stateless 전환)
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        // 4) Redirect via parent's RedirectStrategy (URL 검증 등 가드 유지)
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
