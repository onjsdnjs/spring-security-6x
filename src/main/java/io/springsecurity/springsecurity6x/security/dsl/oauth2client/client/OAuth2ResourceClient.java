package io.springsecurity.springsecurity6x.security.dsl.oauth2client.client;

/**
 * OAuth2 AccessToken을 사용하여 외부 리소스 서버 API를 호출하는 클라이언트 (OAuth2HttpClient 사용)
 */
public class OAuth2ResourceClient {

    private final OAuth2HttpClient httpClient;
    private final OAuth2TokenProvider tokenProvider;

    public OAuth2ResourceClient(OAuth2TokenProvider tokenProvider) {
        this.httpClient = new OAuth2HttpClient();
        this.tokenProvider = tokenProvider;
    }

    public <T> T get(String uri, Class<T> responseType) {
        return httpClient.get(uri, tokenProvider.getAccessToken(), responseType);
    }

    public <T> T post(String uri, Object body, Class<T> responseType) {
        return httpClient.post(uri, body, tokenProvider.getAccessToken(), responseType);
    }
}



