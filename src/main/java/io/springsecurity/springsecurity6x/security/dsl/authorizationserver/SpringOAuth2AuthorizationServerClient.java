package io.springsecurity.springsecurity6x.security.dsl.authorizationserver;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

public class SpringOAuth2AuthorizationServerClient implements AuthorizationServerClient {

    private final RestClient restClient;
    private final String tokenEndpoint;
    private final String clientId;
    private final String clientSecret;

    public SpringOAuth2AuthorizationServerClient(AuthContextProperties properties) {
        this.restClient = RestClient.builder().baseUrl(properties.getExternal().getIssuerUri()).build();
        this.tokenEndpoint = properties.getExternal().getTokenEndpoint();
        this.clientId = properties.getExternal().getClientId();
        this.clientSecret = properties.getExternal().getClientSecret();
    }

    @Override
    public String issueAccessToken() {
        if (restClient == null || tokenEndpoint == null || clientId == null || clientSecret == null) {
            throw new IllegalStateException("AuthorizationServerClient not properly configured.");
        }

        String body = UriComponentsBuilder.newInstance()
                .queryParam("grant_type", "client_credentials")
                .queryParam("client_id", clientId)
                .queryParam("client_secret", clientSecret)
                .queryParam("scope", "openid")
                .build()
                .toString().substring(1);

        Map<String, Object> response = restClient.post()
                .uri(tokenEndpoint)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body)
                .retrieve()
                .body(Map.class);

        assert response != null;
        return (String) response.get("access_token");
    }
}


