package io.springsecurity.springsecurity6x.jwt.properties;

import lombok.Data;

@Data
public class ExternalTokenSettings {

    private String loginUri = "/api/auth/login";
    private String logoutUri = "/api/auth/logout";
    private String refreshUri = "/api/auth/refresh";

    private long accessTokenValidity = 3600000;       // 1시간
    private long refreshTokenValidity = 604800000;    // 7일

    private boolean enableRefreshToken = true;

    private String tokenPrefix = "Bearer ";
    private String rolesClaim = "roles";
    private String scopesClaim = "scopes";

}
