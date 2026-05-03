# egov-boot-web

전자정부 표준프레임워크(eGovFrame Boot 5.0) 기반 샘플 웹 애플리케이션. **netis-auth** OAuth2/OIDC Authorization Server를 통한 로그인 후 게시판 샘플 화면에 진입하도록 구성되어 있다.

---

## 1. 프로젝트 스펙

### 1.1 개요

| 항목 | 값 |
|---|---|
| 포트 | `8081` |
| 런타임 | Java 21 |
| 빌드 | Gradle 8.14 (Groovy DSL) |
| 프레임워크 | Spring Boot 3.5.6 (egovframe-boot-starter-parent 5.0.0 BOM이 끌어올림) |
| 인증 모델 | OAuth2 Authorization Code + OIDC, **JWT-as-Cookie (HttpOnly stateless)** |
| IdP | netis-auth (`http://localhost:9000`) |
| 데이터 | HSQLDB in-memory (샘플 게시판) |

### 1.2 기술 스택

- **표준프레임워크 실행환경**: `egovframe-rte-ptl-mvc`, `egovframe-rte-psl-dataaccess`, `egovframe-rte-fdl-idgnr`, `egovframe-rte-fdl-property`, `egovframe-rte-ptl-reactive`
- **Spring Boot Starter**: `web`, `thymeleaf`, `security`, `oauth2-client`, `oauth2-resource-server`, `validation`, `log4j2`
- **View**: Thymeleaf + thymeleaf-extras-springsecurity6, KRDS UI 컴포넌트
- **DB**: Apache Commons DBCP2 + HSQLDB (in-memory)
- **테스트**: JUnit 5, AssertJ, Mockito, Spring Security Test, **WireMock 3.10** (OIDC 프로바이더 모킹), Selenium

### 1.3 디렉터리 구조 (핵심만)

```
src/main/java/egovframework/example/
├── config/security/
│   ├── SecurityConfig.java                  # 두 SecurityFilterChain (handshake / main)
│   ├── AuthCookieProperties.java            # @ConfigurationProperties("app.auth")
│   ├── CookieUtils.java                     # ResponseCookie 기반 read/write/clear
│   ├── JwtCookieAuthenticationFilter.java   # 매 요청 access_token 쿠키 검증 + 자동 refresh
│   ├── OAuth2LoginSuccessHandler.java       # 핸드셰이크 성공 → 토큰을 쿠키로 직렬화
│   ├── TokenRefreshService.java             # /oauth2/token refresh_token 호출 (race-safe)
│   └── RpInitiatedLogoutHandler.java        # OIDC RP-initiated logout 핸들러
└── sample/                                  # 샘플 게시판 (도메인 코드)

src/main/resources/
├── application.yml                          # 포트, OAuth2 client/provider, 쿠키 정책
└── templates/thymeleaf/sample/              # 샘플 게시판 화면

src/test/java/egovframework/example/config/security/
├── SecurityIntegrationTest.java             # WireMock + MockMvc 슬라이스 통합 테스트
├── RpInitiatedLogoutHandlerTest.java
├── TokenRefreshServiceTest.java
├── JwtCookieAuthenticationFilterTest.java
└── TestKeyFactory.java                      # RSA-2048 정적 키 + 테스트용 토큰 발급
```

---

## 2. 인증 절차

### 2.1 시스템 구성도

```
브라우저 ──► :8081 (egov-boot-web)            ──► :9000 (netis-auth, IdP)
            (RP / OAuth2 client)                  (Authorization Server)
            JWT 쿠키로 stateless 인증            OIDC discovery, JWKS, OAuth2 endpoints
```

- :8081은 **Stateless RP**. 모든 인증 상태는 HttpOnly 쿠키 3종에 담김.
- :9000은 **공유 IdP**. 세션 쿠키로 SSO를 제공하며, OIDC 표준 RP-initiated logout을 지원한다.

### 2.2 SecurityFilterChain 분리

`config/security/SecurityConfig.java`에 두 개의 체인이 등록되어 있다.

| 순서 | 매칭 경로 | 세션 정책 | 용도 |
|---|---|---|---|
| `@Order(1)` 핸드셰이크 | `/oauth2/**`, `/login/**`, `/login` | `IF_REQUIRED` | OAuth2 state/nonce 보관용 임시 세션 (성공 핸들러가 즉시 invalidate) |
| `@Order(2)` 메인 | 그 외 전부 | `STATELESS` | JWT 쿠키 검증 + 자동 refresh, CSRF 비활성 |

이 분리로 "OAuth2 핸드셰이크에는 세션 필요, 그 외엔 stateless" 두 마리 토끼를 잡는다.

### 2.3 토큰 → 쿠키 매핑

| 쿠키 이름 | 내용 | TTL | SameSite | HttpOnly |
|---|---|---|---|---|
| `egov_access_token` | OAuth2 access token (RS256 JWT) | 3600s | Lax | ✓ |
| `egov_refresh_token` | OAuth2 refresh token | 604800s | Strict | ✓ |
| `egov_id_token` | OIDC id_token | 3600s | Strict | ✓ |
| `EGOV_SESSION` | 핸드셰이크 임시 세션 | 핸드셰이크 직후 invalidate | (default) | ✓ |

> **주의**: `EGOV_SESSION`이라는 이름은 의도된 결정. 기본 `JSESSIONID`은 같은 호스트 `localhost`에서 :8081과 :9000이 서로 덮어써 OAuth state lookup을 망가뜨리는 충돌이 있다.

### 2.4 정상 로그인 플로우

```
[1] 브라우저 ──GET── http://localhost:8081/
                           │
                           ▼
[2] 메인 체인 JwtCookieAuthenticationFilter
        access_token 쿠키 없음 → 인증 안 함 → 401
                           │
                           ▼
[3] entry point — 302 to /oauth2/authorization/netis-auth
                           │
                           ▼
[4] 핸드셰이크 체인 OAuth2AuthorizationRequestRedirectFilter
        - 임시 세션 생성 (state, nonce 보관)
        - 302 to http://localhost:9000/oauth2/authorize?response_type=code&...
                           │
                           ▼
[5] netis-auth — 사용자 로그인 → consent 처리 →
        302 to http://localhost:8081/login/oauth2/code/netis-auth?code=...&state=...
                           │
                           ▼
[6] 핸드셰이크 체인 OAuth2LoginAuthenticationFilter
        code → access_token + refresh_token + id_token 교환 (POST /oauth2/token)
                           │
                           ▼
[7] OAuth2LoginSuccessHandler
        a. saved request URL 추출 (세션 무효화 *전에*)
        b. 3개 토큰을 HttpOnly 쿠키로 발행
        c. 임시 세션 invalidate
        d. saved request URL (또는 "/")로 redirect
                           │
                           ▼
[8] GET / — 메인 체인 JwtCookieAuthenticationFilter
        access_token 쿠키 검증 → JwtAuthenticationToken 발행
        Controller 처리 → 게시판 화면 응답
```

### 2.5 자동 토큰 갱신 (silent refresh)

`JwtCookieAuthenticationFilter.doFilterInternal`은 매 요청에서 다음 분기를 따른다.

```
access_token 쿠키 없음     → SecurityContext 변경 없음 → chain 진행 (anonymous)
access_token 유효          → JwtAuthenticationToken 발행 → chain 진행
access_token 만료          → refresh_token으로 /oauth2/token refresh_token grant 호출
                              ├─ 성공 → 새 access/refresh/id 쿠키 재발행 + 인증
                              └─ 실패 → 모든 쿠키 Max-Age=0 + SecurityContext 비움
access_token 변조 (시그니처 실패) → 모든 쿠키 Max-Age=0 + SecurityContext 비움
```

- `TokenRefreshService`는 `ConcurrentHashMap<String, CompletableFuture>`로 같은 refresh token에 대한 동시 갱신 요청을 1회로 합쳐 race를 방지한다.
- 만료/변조 구분은 `JWTParser.parse()`로 raw `exp` 클레임만 읽어 판단한다 (Nimbus의 `iat > exp` 검증 우회용).

### 2.6 RP-initiated 로그아웃 (OIDC 표준)

```
[1] POST :8081/logout
                           │
                           ▼
[2] LogoutFilter — SecurityContext 클리어
                           │
                           ▼
[3] RpInitiatedLogoutHandler.onLogoutSuccess
        a. egov_access/refresh/id_token 쿠키 Max-Age=0
        b. id_token_hint + post_logout_redirect_uri 쿼리스트링 빌드
        c. 302 to http://localhost:9000/connect/logout?id_token_hint=...&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8081%2F
                           │
                           ▼
[4] netis-auth /connect/logout (OIDC end_session_endpoint)
        - id_token_hint 검증 → 해당 사용자의 :9000 세션 invalidate
        - 등록된 post_logout_redirect_uri인지 확인
        - 302 to http://localhost:8081/
                           │
                           ▼
[5] GET :8081/ — JWT 쿠키 없음 + :9000 세션 없음
        → entry point → /oauth2/authorization/netis-auth → :9000 → :9000/login
```

핵심: :9000의 OIDC end_session_endpoint는 **`/connect/logout`** (Spring Authorization Server 표준 경로)이지, `/logout`(폼 로그인 logout)이 아니다. `/logout`으로 호출하면 :9000 세션이 OIDC 방식으로 종료되지 않아 silent SSO로 다시 로그인되는 우회가 발생한다.

### 2.7 CSRF 정책

- **메인 체인 CSRF 비활성화**. JWT 쿠키 자체가 인증 경계이며, `SameSite=Lax`/`Strict`로 cross-site POST가 차단된다.
- Spring Security 6.5의 `STATELESS` 정책 + `CookieCsrfTokenRepository` 조합은 Thymeleaf 폼 토큰과 cookie의 `XSRF-TOKEN`이 매번 다른 값으로 mismatch되는 문제가 있어 회피한 결정.

---

## 3. 빌드 및 실행

### 3.1 사전 요구사항

- **JDK 21** (Gradle Groovy DSL이 Java 26을 지원하지 않음 → 21 권장)
- **netis-auth가 :9000에서 가동 중**이어야 한다. (`gradle.properties`에 `org.gradle.java.home`을 21 경로로 설정 — 이 파일은 gitignore됨.)

### 3.2 명령어

```bash
./gradlew build          # 전체 빌드 + 테스트
./gradlew test           # 테스트만 실행
./gradlew bootRun        # :8081 기동
```

### 3.3 환경변수 (선택)

| 변수 | 디폴트 | 설명 |
|---|---|---|
| `OAUTH_CLIENT_SECRET` | `secret456` | netis-auth에 등록된 `egov-app` client_secret |
| `AUTH_ISSUER_URI` | `http://localhost:9000` | OIDC issuer / discovery base URI |
| `POST_LOGOUT_REDIRECT` | `http://localhost:8081/` | 로그아웃 완료 후 돌아갈 URI (netis-auth에 사전 등록 필요) |

### 3.4 netis-auth 측 사전 등록

`netis-auth/src/main/resources/db/postgres/data.sql`에 다음과 같이 등록되어 있어야 한다.

```sql
client_id:                    egov-app
client_secret:                $2b$12$... (BCrypt hash of OAUTH_CLIENT_SECRET)
authorization_grant_types:    authorization_code, refresh_token
redirect_uris:                http://localhost:8081/login/oauth2/code/netis-auth
post_logout_redirect_uris:    http://localhost:8081/, http://localhost:8081/login?logout=true
scopes:                       openid, profile, email
```

---

## 4. 보안 설계 결정사항 (Why)

| 결정 | 이유 |
|---|---|
| 세션 모델이 아닌 JWT-as-Cookie | 수평 확장 시 세션 동기화 불필요. 토큰이 인증 정보 자체이므로 stateless. |
| 토큰을 쿠키로 (LocalStorage 아님) | XSS 노출 위험 차단 (HttpOnly). SPA가 아니므로 쿠키 자동 전송이 자연스러움. |
| handshake / main 체인 분리 | OAuth2 핸드셰이크는 세션 필요, 그 외엔 stateless로 분리. |
| RefreshToken `SameSite=Strict` | refresh_token은 1차 사이트 컨텍스트에서만 사용. 노출면 최소화. |
| CSRF 비활성화 (메인 체인) | 위 2.7 참고. JWT 쿠키 + SameSite로 대체 보호. |
| Refresh race 방지 (CompletableFuture 디듀프) | 동일 refresh token으로 동시 호출되면 IdP가 한 번만 회전 처리, 나머지는 invalid가 되어 사용자가 강제 로그아웃됨. |

---

## 5. 테스트

```bash
./gradlew test
```

| 테스트 | 검증 내용 |
|---|---|
| `SecurityIntegrationTest` | WireMock OIDC 프로바이더로 5종 시나리오 (anonymous→리다이렉트, valid JWT→200, expired+refresh→재발급, CSRF 비활성 POST→200, logout→`/connect/logout`로 redirect) |
| `JwtCookieAuthenticationFilterTest` | JWT 검증 7종 (없음/유효/만료+refresh/변조/refresh실패 등) |
| `TokenRefreshServiceTest` | refresh_token grant 정상/실패/race 디듀프 |
| `RpInitiatedLogoutHandlerTest` | redirect URL, id_token_hint, 쿠키 클리어 헤더 |

---

## 6. 트러블슈팅 노트

E2E 검증 중 발견했던 이슈들과 그 원인. 같은 패턴이 재발하지 않도록 기록.

| 이슈 | 원인 | 해결 |
|---|---|---|
| 로그아웃 후 재로그인이 메인으로 안 옴 / 로그아웃 후 :8081 직접 접근 시 자동 로그인 | `RpInitiatedLogoutHandler`가 OIDC 표준 `/connect/logout`이 아닌 `:9000/logout`(form-login logout)으로 redirect | path를 `/connect/logout`으로 변경 (커밋 `15bf7df`) |
| OAuth state lookup 실패 (`authorization_request_not_found`) | :8081/:9000이 같은 `localhost` 도메인에서 `JSESSIONID`를 서로 덮어씀 | `server.servlet.session.cookie.name: EGOV_SESSION` |
| Thymeleaf 폼의 CSRF 토큰이 매번 mismatch → 403 | Spring Security 6.5 STATELESS + `CookieCsrfTokenRepository` 조합 결함 | 메인 체인 CSRF 비활성화 + `th:if="${_csrf != null}"` 가드 |
| OAuth2LoginSuccessHandler가 saved request를 못 찾음 | 부모 `super.onAuthenticationSuccess` 호출이 `session.invalidate()` 후라 saved URL 손실 | `SavedRequestAwareAuthenticationSuccessHandler`를 properly 상속, saved URL을 invalidate 전에 추출 |
| TestKeyFactory에서 만료 토큰 생성 시 `expiresAt must be after issuedAt` | Nimbus가 `iat > exp` 토큰을 파싱 단계에서 거부 | 만료 판별을 `JWTParser.parse()`로 raw `exp` 클레임 직접 읽기 |

---

## 7. 관련 워크스페이스 프로젝트

- **netis-auth** (`:9000`): Spring Authorization Server. 이 프로젝트의 IdP.
- **netis-backend** (`:8080`): 별도 백엔드. JWT 검증 시 같은 issuer (`:9000`)의 JWKS를 참조.
- **nuxt_practice** (`:3000`): Nuxt 프론트엔드. 같은 IdP를 PKCE 방식으로 사용.

이 프로젝트의 OAuth2 client 등록은 `netis-auth/src/main/resources/db/postgres/data.sql`의 `egov-app` 엔트리에 있다.
