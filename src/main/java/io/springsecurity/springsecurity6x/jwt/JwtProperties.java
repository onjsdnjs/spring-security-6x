package io.springsecurity.springsecurity6x.jwt;

import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
@ConfigurationProperties(prefix = "spring.jwt")
public class JwtProperties {
    private TokenService tokenService;
    private RefreshTokenStore refreshTokenStore;
    private String tokenPrefix = "Bearer ";
    private long accessTokenValidity = 3600000;
    private long refreshTokenValidity = 604800000;
    private String loginUri = "/api/auth/login";
    private String logoutUri = "/api/auth/logout";
    private String refreshUri = "/api/auth/refresh";
    private String rolesClaim = "roles";
    private String scopesClaim = "scopes";
    private boolean enableRefreshToken = true;
    private Map<String, String> scopeToPattern = new HashMap<>();
    private String provider = "jwt";
}
