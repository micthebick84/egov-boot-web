package egovframework.example.config.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySource;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthCookiePropertiesTest {

    @Test
    void bindsAllPropertiesFromYamlEquivalentMap() {
        Map<String, Object> props = Map.of(
                "app.auth.cookie.secure", "false",
                "app.auth.cookie.same-site-default", "Lax",
                "app.auth.cookie.same-site-strict", "Strict",
                "app.auth.cookie.access-token-name", "egov_access_token",
                "app.auth.cookie.refresh-token-name", "egov_refresh_token",
                "app.auth.cookie.id-token-name", "egov_id_token",
                "app.auth.cookie.access-token-max-age-seconds", "3600",
                "app.auth.cookie.refresh-token-max-age-seconds", "604800",
                "app.auth.post-logout-redirect-uri", "http://localhost:8081/"
        );
        ConfigurationPropertySource source = new MapConfigurationPropertySource(props);

        AuthCookieProperties bound = new Binder(source)
                .bind("app.auth", AuthCookieProperties.class)
                .get();

        assertThat(bound.getCookie().isSecure()).isFalse();
        assertThat(bound.getCookie().getSameSiteDefault()).isEqualTo("Lax");
        assertThat(bound.getCookie().getSameSiteStrict()).isEqualTo("Strict");
        assertThat(bound.getCookie().getAccessTokenName()).isEqualTo("egov_access_token");
        assertThat(bound.getCookie().getRefreshTokenName()).isEqualTo("egov_refresh_token");
        assertThat(bound.getCookie().getIdTokenName()).isEqualTo("egov_id_token");
        assertThat(bound.getCookie().getAccessTokenMaxAgeSeconds()).isEqualTo(3600);
        assertThat(bound.getCookie().getRefreshTokenMaxAgeSeconds()).isEqualTo(604800);
        assertThat(bound.getPostLogoutRedirectUri()).isEqualTo("http://localhost:8081/");
    }
}
