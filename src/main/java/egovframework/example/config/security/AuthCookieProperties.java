package egovframework.example.config.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.auth")
public class AuthCookieProperties {

    private final Cookie cookie = new Cookie();
    private String postLogoutRedirectUri;

    @Getter
    @Setter
    public static class Cookie {
        private boolean secure;
        private String sameSiteDefault = "Lax";
        private String sameSiteStrict = "Strict";
        private String accessTokenName = "egov_access_token";
        private String refreshTokenName = "egov_refresh_token";
        private String idTokenName = "egov_id_token";
        private int accessTokenMaxAgeSeconds = 3600;
        private int refreshTokenMaxAgeSeconds = 604800;
    }
}
