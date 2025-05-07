package io.springsecurity.springsecurity6x.security.core.feature.state.oauth2.client;

import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * OAuth2 AccessToken을 인가서버로부터 발급받고 관리하는 컴포넌트
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

    /**
     * 현재 유효한 AccessToken을 반환 (필요시 자동 갱신)
     */
    public synchronized String getAccessToken() {
        OAuth2AccessToken token = cachedToken.get();
        if (token == null || token.isExpired()) {
            token = requestNewAccessToken();
            cachedToken.set(token);
        }
        return token.tokenValue();
    }

    /**
     * 인가서버로부터 새 AccessToken을 요청
     */
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

        if (response == null || response.getAccessToken() == null) {
            throw new IllegalStateException("인가 서버로부터 AccessToken을 정상적으로 발급받지 못했습니다.");
        }

        return new OAuth2AccessToken(
                response.getAccessToken(),
                Instant.now().plusSeconds(response.getExpiresIn() - 60) // 만료 1분 전으로 설정
        );
    }

    /**
     * introspect 검증용 URI 반환 (tokenUri로부터 유추)
     */
    public String getIntrospectUri() {
        // 일반적으로 introspect endpoint는 "/oauth2/introspect" 패턴을 따른다
        return tokenUri.replace("/token", "/introspect");
    }
}




