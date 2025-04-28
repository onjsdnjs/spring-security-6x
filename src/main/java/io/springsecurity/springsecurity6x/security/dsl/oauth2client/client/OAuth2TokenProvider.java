package io.springsecurity.springsecurity6x.security.dsl.oauth2client.client;

import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * OAuth2 AccessToken을 인가서버로부터 발급받고 관리하는 컴포넌트 (OAuth2HttpClient 사용)
 */
public class OAuth2TokenProvider {

    private final OAuth2HttpClient httpClient;
    private final String tokenUri;
    private final OAuth2ClientRequest clientRequest;

    private final AtomicReference<OAuth2AccessToken> cachedToken = new AtomicReference<>();

    public OAuth2TokenProvider(String tokenUri, OAuth2ClientRequest clientRequest) {
        this.httpClient = new OAuth2HttpClient();
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
        String body = UriComponentsBuilder.newInstance()
                .queryParam("grant_type", "client_credentials")
                .queryParam("client_id", clientRequest.clientId())
                .queryParam("client_secret", clientRequest.clientSecret())
                .queryParam("scope", clientRequest.scope())
                .build()
                .toString()
                .substring(1);  // 맨 앞 '?' 제거

        OAuth2AccessTokenResponse response = httpClient.post(
                tokenUri,
                body,
                OAuth2AccessTokenResponse.class
        );

        return new OAuth2AccessToken(
                response.getAccessToken(),
                Instant.now().plusSeconds(response.getExpiresIn() - 60)
        );
    }
}



