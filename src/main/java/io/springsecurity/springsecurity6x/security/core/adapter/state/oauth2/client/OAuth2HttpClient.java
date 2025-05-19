package io.springsecurity.springsecurity6x.security.core.adapter.state.oauth2.client;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

public class OAuth2HttpClient {

    private final RestClient restClient;

    public OAuth2HttpClient() {
        this.restClient = RestClient.builder().build();
    }

    public <T> T get(String uri, String bearerToken, Class<T> responseType) {
        try {
            return restClient.get()
                    .uri(uri)
                    .headers(headers -> headers.setBearerAuth(bearerToken))
                    .retrieve()
                    .body(responseType);
        } catch (RestClientResponseException e) {
            throw new RuntimeException("리소스 서버 GET 요청 실패: " + e.getResponseBodyAsString(), e);
        }
    }

    public <T> T post(String uri, String formBody, Class<T> responseType) {
        try {
            return restClient.post()
                    .uri(uri)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .body(formBody)
                    .retrieve()
                    .body(responseType);
        } catch (RestClientResponseException e) {
            throw new RuntimeException("인가 서버 POST 요청 실패: " + e.getResponseBodyAsString(), e);
        }
    }

    public <T> T post(String uri, Object jsonBody, String bearerToken, Class<T> responseType) {
        try {
            return restClient.post()
                    .uri(uri)
                    .headers(headers -> {
                        headers.setBearerAuth(bearerToken);
                        headers.setContentType(MediaType.APPLICATION_JSON);
                    })
                    .body(jsonBody)
                    .retrieve()
                    .body(responseType);
        } catch (RestClientResponseException e) {
            throw new RuntimeException("리소스 서버 POST 요청 실패: " + e.getResponseBodyAsString(), e);
        }
    }
}

