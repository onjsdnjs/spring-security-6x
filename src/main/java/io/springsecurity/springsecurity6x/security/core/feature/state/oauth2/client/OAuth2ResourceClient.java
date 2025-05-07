package io.springsecurity.springsecurity6x.security.core.feature.state.oauth2.client;

import java.util.Map;

public class OAuth2ResourceClient {

    private final OAuth2HttpClient httpClient;
    private final OAuth2TokenProvider tokenProvider;

    public OAuth2ResourceClient(OAuth2TokenProvider tokenProvider) {
        this.httpClient = new OAuth2HttpClient();
        this.tokenProvider = tokenProvider;
    }

    public String issueAccessToken(String username) {
        return tokenProvider.getAccessToken();
    }

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

    public OAuth2IntrospectionResponse getUserInfo(String accessToken) {
        Map<String, Object> introspectionResponse = httpClient.post(
                tokenProvider.getIntrospectUri(),
                "token=" + accessToken,
                Map.class
        );

        return new OAuth2IntrospectionResponse(
                (Boolean) introspectionResponse.getOrDefault("active", false),
                (String) introspectionResponse.getOrDefault("username", null),
                (String) introspectionResponse.getOrDefault("scope", ""),
                introspectionResponse.get("exp") != null
                        ? ((Number) introspectionResponse.get("exp")).longValue()
                        : null
        );
    }

    public <T> T get(String uri, Class<T> responseType) {
        return httpClient.get(uri, tokenProvider.getAccessToken(), responseType);
    }

    public <T> T post(String uri, Object body, Class<T> responseType) {
        return httpClient.post(uri, body, tokenProvider.getAccessToken(), responseType);
    }
}
