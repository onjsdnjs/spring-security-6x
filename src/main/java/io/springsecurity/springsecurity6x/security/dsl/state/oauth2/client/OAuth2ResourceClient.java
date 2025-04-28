package io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client;

import java.util.Map;

public class OAuth2ResourceClient {

    private final OAuth2HttpClient httpClient;
    private final OAuth2TokenProvider tokenProvider;

    public OAuth2ResourceClient(OAuth2TokenProvider tokenProvider) {
        this.httpClient = new OAuth2HttpClient();
        this.tokenProvider = tokenProvider;
    }

    /**
     * 액세스 토큰을 새로 발급받는다.
     */
    public String issueAccessToken(String username) {
        // OAuth2에서는 username 기반이 아니고, Client Credentials로 발급
        return tokenProvider.getAccessToken();
    }

    /**
     * 액세스 토큰 유효성 검사
     */
    public boolean validateAccessToken(String accessToken) {
        try {
            Map<String, Object> introspectionResponse = httpClient.post(
                    tokenProvider.getIntrospectUri(),
                    "token=" + accessToken,
                    Map.class
            );
            Boolean active = (Boolean) introspectionResponse.get("active");
            return Boolean.TRUE.equals(active);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 보호된 리소스에 GET 요청
     */
    public <T> T get(String uri, Class<T> responseType) {
        return httpClient.get(uri, tokenProvider.getAccessToken(), responseType);
    }

    /**
     * 보호된 리소스에 POST 요청
     */
    public <T> T post(String uri, Object body, Class<T> responseType) {
        return httpClient.post(uri, body, tokenProvider.getAccessToken(), responseType);
    }
}




