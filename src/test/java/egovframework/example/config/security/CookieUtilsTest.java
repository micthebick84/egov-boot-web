package egovframework.example.config.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class CookieUtilsTest {

    private final CookieUtils cookieUtils = new CookieUtils();

    @Test
    void writeAccessCookieSetsHttpOnlyAndSameSiteLaxAndMaxAge() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieUtils.writeCookie(response, "egov_access_token", "abc123", 3600, "Lax", false);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).isNotNull();
        assertThat(header).contains("egov_access_token=abc123");
        assertThat(header).contains("Max-Age=3600");
        assertThat(header).contains("Path=/");
        assertThat(header).contains("HttpOnly");
        assertThat(header).contains("SameSite=Lax");
        assertThat(header).doesNotContain("Secure");
    }

    @Test
    void writeRefreshCookieSetsSameSiteStrictAndSecureWhenEnabled() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieUtils.writeCookie(response, "egov_refresh_token", "rt-xyz", 604800, "Strict", true);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains("SameSite=Strict");
        assertThat(header).contains("Secure");
    }

    @Test
    void clearCookieEmitsMaxAgeZero() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieUtils.clearCookie(response, "egov_access_token", false);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains("egov_access_token=");
        assertThat(header).contains("Max-Age=0");
        assertThat(header).contains("HttpOnly");
        assertThat(header).contains("Path=/");
    }

    @Test
    void readCookieReturnsValueWhenPresent() {
        jakarta.servlet.http.Cookie cookie = new jakarta.servlet.http.Cookie("egov_access_token", "abc");
        org.springframework.mock.web.MockHttpServletRequest request =
                new org.springframework.mock.web.MockHttpServletRequest();
        request.setCookies(cookie);

        assertThat(cookieUtils.readCookie(request, "egov_access_token")).contains("abc");
        assertThat(cookieUtils.readCookie(request, "missing")).isEmpty();
    }
}
