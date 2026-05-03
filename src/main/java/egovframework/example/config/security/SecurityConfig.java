package egovframework.example.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

@Configuration
public class SecurityConfig {

    /**
     * OAuth2 핸드셰이크 전용 체인: /oauth2/**, /login/** 경로에서만 동작.
     * IF_REQUIRED 세션을 사용해 state/nonce 보관 (핸드셰이크 직후 success handler가 invalidate).
     */
    @Bean
    @Order(1)
    public SecurityFilterChain handshakeSecurityFilterChain(HttpSecurity http,
                                                            OAuth2LoginSuccessHandler loginSuccessHandler)
            throws Exception {
        http
                .securityMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/oauth2/**"),
                        new AntPathRequestMatcher("/login/**"),
                        new AntPathRequestMatcher("/login")
                ))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(a -> a
                        .anyRequest().permitAll()
                )
                .oauth2Login(o -> o
                        .successHandler(loginSuccessHandler)
                        .failureUrl("/login?error")
                );
        return http.build();
    }

    /**
     * 메인 체인: 그 외 모든 경로. STATELESS, JWT 쿠키 필터로 인증.
     * /logout은 RpInitiatedLogoutHandler가 처리, 정적 리소스는 permitAll, 그 외는 authenticated.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain mainSecurityFilterChain(HttpSecurity http,
                                                       JwtDecoder jwtDecoder,
                                                       TokenRefreshService refreshService,
                                                       CookieUtils cookieUtils,
                                                       AuthCookieProperties props,
                                                       LogoutSuccessHandler logoutSuccessHandler) throws Exception {
        JwtCookieAuthenticationFilter jwtFilter =
                new JwtCookieAuthenticationFilter(jwtDecoder, refreshService, cookieUtils, props);

        // CSRF는 비활성화: JWT 쿠키 자체가 인증 경계이며 SameSite=Lax로 cross-site POST 차단됨.
        // Spring Security 6.5 STATELESS + CookieCsrfTokenRepository는 Thymeleaf 폼 토큰과
        // 쿠키 토큰 동기화 문제가 있어 해당 조합을 회피.
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/css/**", "/js/**", "/img/**", "/fonts/**", "/error/**", "/favicon.ico")
                            .permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(e -> e.authenticationEntryPoint((req, res, ex) ->
                        res.sendRedirect("/oauth2/authorization/netis-auth")))
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .deleteCookies("JSESSIONID")
                );

        return http.build();
    }
}
