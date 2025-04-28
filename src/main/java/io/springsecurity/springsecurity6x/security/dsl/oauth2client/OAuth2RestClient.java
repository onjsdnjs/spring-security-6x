package io.springsecurity.springsecurity6x.security.dsl.oauth2client;

import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

public class OAuth2RestClient {

    private final RestClient restClient;
    private final OAuth2TokenProvider tokenProvider;

    public OAuth2RestClient(OAuth2TokenProvider tokenProvider) {
        this.restClient = RestClient.builder().build();
        this.tokenProvider = tokenProvider;
    }

    public <T> T get(String uri, Class<T> responseType) {
        try {
            return restClient.get()
                    .uri(uri)
                    .headers(headers -> headers.setBearerAuth(tokenProvider.getAccessToken()))
                    .retrieve()
                    .body(responseType);
        } catch (RestClientResponseException e) {
            throw new RuntimeException("리소스 서버 GET 요청 실패: " + e.getResponseBodyAsString(), e);
        }
    }

    public <T> T post(String uri, Object body, Class<T> responseType) {
        try {
            return restClient.post()
                    .uri(uri)
                    .headers(headers -> {
                        headers.setBearerAuth(tokenProvider.getAccessToken());
                        headers.setContentType(MediaType.APPLICATION_JSON);
                    })
                    .body(body)
                    .retrieve()
                    .body(responseType);
        } catch (RestClientResponseException e) {
            throw new RuntimeException("리소스 서버 POST 요청 실패: " + e.getResponseBodyAsString(), e);
        }
    }
}

