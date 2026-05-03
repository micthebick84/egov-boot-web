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
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

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

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

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

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
