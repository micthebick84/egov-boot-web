package egovframework.example.config.security;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class RpInitiatedLogoutHandlerTest {

    private final String issuer = "http://localhost:9000";
    private final String postLogoutRedirect = "http://localhost:8081/";
    private final CookieUtils cookieUtils = new CookieUtils();
    private final AuthCookieProperties props = setupProps();

    private AuthCookieProperties setupProps() {
        AuthCookieProperties p = new AuthCookieProperties();
        p.setPostLogoutRedirectUri(postLogoutRedirect);
        return p;
    }

    private final RpInitiatedLogoutHandler handler =
            new RpInitiatedLogoutHandler(issuer, cookieUtils, props);

    @Test
    void redirectsToAuthLogoutWithIdTokenHintAndPostLogoutRedirect() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("egov_id_token", "id-token-value"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onLogoutSuccess(request, response, null);

        String redirect = response.getRedirectedUrl();
        assertThat(redirect).startsWith("http://localhost:9000/logout?");
        assertThat(redirect).contains("id_token_hint=id-token-value");
        assertThat(redirect).contains("post_logout_redirect_uri=" +
                UriUtils.encode(postLogoutRedirect, StandardCharsets.UTF_8));
    }

    @Test
    void clearsAllAuthCookies() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("egov_id_token", "x"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onLogoutSuccess(request, response, null);

        var cookies = response.getHeaders("Set-Cookie");
        assertThat(cookies).anyMatch(c -> c.contains("egov_access_token=") && c.contains("Max-Age=0"));
        assertThat(cookies).anyMatch(c -> c.contains("egov_refresh_token=") && c.contains("Max-Age=0"));
        assertThat(cookies).anyMatch(c -> c.contains("egov_id_token=") && c.contains("Max-Age=0"));
    }

    @Test
    void omitsIdTokenHintWhenCookieAbsent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onLogoutSuccess(request, response, null);

        String redirect = response.getRedirectedUrl();
        assertThat(redirect).startsWith("http://localhost:9000/logout?");
        assertThat(redirect).doesNotContain("id_token_hint=");
        assertThat(redirect).contains("post_logout_redirect_uri=");
    }
}
