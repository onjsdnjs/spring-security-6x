package io.springsecurity.springsecurity6x.security.dsl.oauth2client;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * OAuth2 인가 서버에 client_credentials 요청을 보내고
 * AccessToken을 발급받고 관리하는 컴포넌트
 */
public class OAuth2TokenProvider {

    private final RestClient restClient;
    private final String tokenUri;
    private final OAuth2ClientRequest clientRequest;

    private final AtomicReference<OAuth2AccessToken> cachedToken = new AtomicReference<>();

    public OAuth2TokenProvider(String tokenUri, OAuth2ClientRequest clientRequest) {
        this.restClient = RestClient.builder().build();
        this.tokenUri = tokenUri;
        this.clientRequest = clientRequest;
    }

    public synchronized String getAccessToken() {
        OAuth2AccessToken token = cachedToken.get();
        if (token == null || token.isExpired()) {
            token = requestNewAccessToken();
            cachedToken.set(token);
        }
        return token.tokenValue();
    }

    private OAuth2AccessToken requestNewAccessToken() {
        try {
            String body = UriComponentsBuilder.newInstance()
                    .queryParam("grant_type", "client_credentials")
                    .queryParam("client_id", clientRequest.clientId())
                    .queryParam("client_secret", clientRequest.clientSecret())
                    .queryParam("scope", clientRequest.scope())
                    .build()
                    .toString()
                    .substring(1);  // 맨 앞 '?' 제거

            OAuth2AccessTokenResponse response = restClient.post()
                    .uri(tokenUri)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .body(body)
                    .retrieve()
                    .body(OAuth2AccessTokenResponse.class);

            return new OAuth2AccessToken(
                    response.getAccessToken(),
                    Instant.now().plusSeconds(response.getExpiresIn() - 60)  // 안전 여유 60초
            );

        } catch (RestClientResponseException e) {
            throw new RuntimeException("AccessToken 발급 실패: " + e.getResponseBodyAsString(), e);
        }
    }
}


