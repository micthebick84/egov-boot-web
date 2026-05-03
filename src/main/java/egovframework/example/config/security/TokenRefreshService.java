package egovframework.example.config.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class TokenRefreshService {

    private final RestClient restClient;
    private final String basicAuth;
    private final ConcurrentHashMap<String, CompletableFuture<Optional<TokenResponse>>> inFlight =
            new ConcurrentHashMap<>();

    public TokenRefreshService(RestClient.Builder restClientBuilder,
                               @Value("${spring.security.oauth2.client.provider.netis-auth.issuer-uri}")
                               String issuerUri,
                               @Value("${spring.security.oauth2.client.registration.netis-auth.client-id}")
                               String clientId,
                               @Value("${spring.security.oauth2.client.registration.netis-auth.client-secret}")
                               String clientSecret) {
        this(restClientBuilder.baseUrl(issuerUri).build(), clientId, clientSecret);
    }

    // 테스트용 생성자 (package-private)
    TokenRefreshService(RestClient restClient, String clientId, String clientSecret) {
        this.restClient = restClient;
        this.basicAuth = Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes());
    }

    public Optional<TokenResponse> refresh(String refreshToken) {
        CompletableFuture<Optional<TokenResponse>> future = inFlight.computeIfAbsent(
                refreshToken,
                rt -> CompletableFuture.supplyAsync(() -> doRefresh(rt))
        );
        try {
            return future.get(15, TimeUnit.SECONDS);
        } catch (Exception e) {
            return Optional.empty();
        } finally {
            inFlight.remove(refreshToken, future);
        }
    }

    private Optional<TokenResponse> doRefresh(String refreshToken) {
        try {
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "refresh_token");
            form.add("refresh_token", refreshToken);

            TokenResponse body = restClient.post()
                    .uri("/oauth2/token")
                    .header(HttpHeaders.AUTHORIZATION, "Basic " + basicAuth)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(TokenResponse.class);
            return Optional.ofNullable(body);
        } catch (RestClientResponseException ex) {
            return Optional.empty();
        } catch (Exception ex) {
            return Optional.empty();
        }
    }

    public record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("refresh_token") String refreshToken,
            @JsonProperty("id_token") String idToken,
            @JsonProperty("expires_in") int expiresInSeconds,
            @JsonProperty("token_type") String tokenType
    ) {}
}
