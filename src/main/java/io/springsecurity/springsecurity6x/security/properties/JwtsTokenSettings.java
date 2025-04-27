package io.springsecurity.springsecurity6x.security.properties;

import lombok.Data;

@Data
public class JwtsTokenSettings {

    private String loginUri = "/api/auth/login";
    private String logoutUri = "/api/auth/logout";
    private String refreshUri = "/api/auth/refresh";

    private long accessTokenValidity = 3600000;       // 1시간
    private long refreshTokenValidity = 604800000;    // 7일
    private long refreshRotateThreshold = 43200000; // 기본 12시간 (밀리초)

    private boolean enableRefreshToken = true;

    private String tokenPrefix = "Bearer ";
    private String rolesClaim = "roles";
    private String scopesClaim = "scopes";
}

