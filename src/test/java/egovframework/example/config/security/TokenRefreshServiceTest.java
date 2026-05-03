package egovframework.example.config.security;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

class TokenRefreshServiceTest {

    private WireMockServer wireMock;
    private TokenRefreshService service;

    @BeforeEach
    void setUp() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();

        RestClient restClient = RestClient.builder()
                .baseUrl("http://localhost:" + wireMock.port())
                .build();

        service = new TokenRefreshService(restClient, "egov-app", "secret456");
    }

    @AfterEach
    void tearDown() {
        wireMock.stop();
    }

    @Test
    void successResponseReturnsParsedTokens() {
        wireMock.stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "access_token":"new-at",
                                  "refresh_token":"new-rt",
                                  "id_token":"new-it",
                                  "token_type":"Bearer",
                                  "expires_in":3600
                                }
                                """)));

        Optional<TokenRefreshService.TokenResponse> result = service.refresh("old-rt");

        assertThat(result).isPresent();
        assertThat(result.get().accessToken()).isEqualTo("new-at");
        assertThat(result.get().refreshToken()).isEqualTo("new-rt");
        assertThat(result.get().idToken()).isEqualTo("new-it");
        assertThat(result.get().expiresInSeconds()).isEqualTo(3600);
    }

    @Test
    void clientErrorReturnsEmpty() {
        wireMock.stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse().withStatus(400)
                        .withBody("{\"error\":\"invalid_grant\"}")));

        Optional<TokenRefreshService.TokenResponse> result = service.refresh("invalid-rt");

        assertThat(result).isEmpty();
    }

    @Test
    void serverErrorReturnsEmpty() {
        wireMock.stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse().withStatus(503)));

        Optional<TokenRefreshService.TokenResponse> result = service.refresh("old-rt");

        assertThat(result).isEmpty();
    }

    @Test
    void concurrentCallsForSameTokenShareSingleHttpRequest() throws Exception {
        wireMock.stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withFixedDelay(150)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"access_token":"shared-at","refresh_token":"shared-rt",
                                 "id_token":"shared-it","token_type":"Bearer","expires_in":3600}
                                """)));

        ExecutorService pool = Executors.newFixedThreadPool(5);
        try {
            List<CompletableFuture<Optional<TokenRefreshService.TokenResponse>>> futures = List.of(
                    CompletableFuture.supplyAsync(() -> service.refresh("same-rt"), pool),
                    CompletableFuture.supplyAsync(() -> service.refresh("same-rt"), pool),
                    CompletableFuture.supplyAsync(() -> service.refresh("same-rt"), pool),
                    CompletableFuture.supplyAsync(() -> service.refresh("same-rt"), pool),
                    CompletableFuture.supplyAsync(() -> service.refresh("same-rt"), pool)
            );
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).get();
            for (var f : futures) {
                assertThat(f.get()).isPresent();
                assertThat(f.get().get().accessToken()).isEqualTo("shared-at");
            }
        } finally {
            pool.shutdown();
        }

        wireMock.verify(1, postRequestedFor(urlEqualTo("/oauth2/token")));
    }
}
