# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Orientation

**Read `README.md` first.** It is the authoritative architecture document — Korean, but exhaustive: filter-chain split, full OAuth2 + OIDC sequence diagrams, cookie/TTL/SameSite table, design rationale ("Why" section), and a troubleshooting log of issues already burned-in. Do not duplicate that content here; treat the README as load-bearing and update it when behavior changes.

This is **one of three projects** in the wider Netis workspace (parent `~/IdeaProjects/CLAUDE.md`). This repo is the eGovFrame Boot 5.0 RP that delegates auth to `netis-auth` (`:9000`). It is unrelated to `netis-backend`.

## Build & Test

```bash
./gradlew bootRun                                      # run on :8081 (requires netis-auth on :9000)
./gradlew build                                        # full build + tests
./gradlew test                                         # all tests
./gradlew test --tests "SecurityIntegrationTest"       # one class
./gradlew test --tests "*JwtCookieAuthenticationFilterTest.expiredToken*"   # one method (glob)
./gradlew test -i                                      # info logs (test stdout/stderr)
```

- **Java 21 required.** Gradle 8.14 Groovy DSL does not support Java 26. `gradle.properties` (gitignored) is where `org.gradle.java.home` is pinned locally.
- **No Maven**, despite leftover `mvnw*` patterns in `.gitignore` from the pre-Gradle layout.
- Tests use HSQLDB in-memory + WireMock 3.10 (mocks `:9000` OIDC discovery + JWKS + `/oauth2/token`). No external services needed for `./gradlew test`.

## Architecture Invariants (easy to break)

These are the constraints that took commits to discover. Don't undo them without understanding why.

- **Two `SecurityFilterChain`s, ordered**: `@Order(1)` for `/oauth2/**`, `/login/**`, `/login` with `IF_REQUIRED` session (OAuth2 needs session for `state`/`nonce`); `@Order(2)` for everything else with `STATELESS` session + JWT-cookie auth. Don't merge them. See `config/security/SecurityConfig.java`.
- **CSRF is intentionally disabled on the main chain.** Spring Security 6.5 `STATELESS` + `CookieCsrfTokenRepository` produces token-mismatch on every Thymeleaf form. Protection comes from the JWT-cookie boundary + `SameSite=Lax/Strict`. Re-enabling CSRF will break every POST.
- **Session cookie is `EGOV_SESSION`, not `JSESSIONID`.** `localhost:8081` and `localhost:9000` are same-host and would otherwise overwrite each other's session cookie, killing OAuth2 `state` lookup with `authorization_request_not_found`. Set in `application.yml: server.servlet.session.cookie.name`.
- **OIDC logout target is `/connect/logout`, not `/logout`.** `/logout` on netis-auth is the form-login endpoint and does not run the OIDC end_session flow → silent SSO will re-log the user in. See `RpInitiatedLogoutHandler` and commit `15bf7df`.
- **`OAuth2LoginSuccessHandler` must read the saved-request URL *before* invalidating the handshake session.** Calling `super.onAuthenticationSuccess` after `session.invalidate()` loses it.
- **Expired-token detection uses `JWTParser.parse()` to read raw `exp`,** not Nimbus's validating parse. Nimbus rejects `iat > exp` tokens at parse time, which is exactly what `TestKeyFactory` produces for the expired-then-refresh test.
- **`TokenRefreshService` deduplicates concurrent refreshes via `ConcurrentHashMap<String, CompletableFuture>`.** netis-auth rotates refresh tokens, so two parallel calls with the same refresh token would invalidate one of them and force-logout the user. Don't simplify this away.

## Configuration knobs

`application.yml` reads three env vars with defaults: `OAUTH_CLIENT_SECRET` (`secret456`), `AUTH_ISSUER_URI` (`http://localhost:9000`), `POST_LOGOUT_REDIRECT` (`http://localhost:8081/`). The `post_logout_redirect_uri` must be pre-registered on the netis-auth side (`netis-auth/src/main/resources/db/postgres/data.sql`, client `egov-app`).

Cookie behavior is type-safe via `AuthCookieProperties` (`@ConfigurationProperties("app.auth")`) — change cookie names/TTLs/SameSite there, not by string-literaling them.

## Conventions

- **README and commit messages are Korean.** Recent log style: `fix(security): ...`, `test(security): ...`, `feat(view): ...`. Match this when adding commits.
- **Lombok** is used; no separate linter is configured.
- All security code lives under `egovframework.example.config.security`. Sample CRUD lives under `egovframework.example.sample` and is intentionally untouched eGovFrame boilerplate — don't refactor it as part of security work.
- Test-side RSA keys + token minting live in `TestKeyFactory`. Use it for any new security test instead of generating keys ad-hoc.
