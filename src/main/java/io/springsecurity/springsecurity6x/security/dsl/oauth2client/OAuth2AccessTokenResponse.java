package io.springsecurity.springsecurity6x.security.dsl.oauth2client;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OAuth2AccessTokenResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("expires_in")
    private int expiresIn;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("scope")
    private String scope;

    // 기본 생성자 (RestClient가 필요로 함)
    public OAuth2AccessTokenResponse() {}

    public String getAccessToken() {
        return accessToken;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getScope() {
        return scope;
    }
}

