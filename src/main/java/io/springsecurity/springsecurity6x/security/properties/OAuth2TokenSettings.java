package io.springsecurity.springsecurity6x.security.properties;

import lombok.Data;

@Data
public class OAuth2TokenSettings {

    private String clientId = "default-client";
    private String clientSecret = "default-secret";
    private String issuerUri = "http://localhost:9000";
    private String tokenEndpoint = "/oauth2/token";
    private String scope = "read";

    private long accessTokenTtl = 3600000;     // 1시간
    private long refreshTokenTtl = 604800000;  // 7일
}

