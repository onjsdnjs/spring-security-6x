package io.springsecurity.springsecurity6x.security.properties;

import io.springsecurity.springsecurity6x.security.enums.AuthStateMode;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.TokenIssuer;
import io.springsecurity.springsecurity6x.security.enums.TokenTransportType;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.EnumSet;
import java.util.Set;

@Data
@ConfigurationProperties(prefix = "spring.auth")
public class AuthContextProperties {

    /**
     * 인증 상태 유지 방식 선택 (JWT, SESSION)
     */
    private AuthStateMode authStateMode = AuthStateMode.JWT;

    /**
     * 인증 상태 유지 방식 선택 (JWT, SESSION)
     */
    private TokenTransportType tokenTransportType = TokenTransportType.HEADER;

    /**
     * 토큰 발급/검증의 방식 설정
     */
    private TokenIssuer tokenIssuer = TokenIssuer.INTERNAL;

    /**
     * 허용할 인증 방식 목록 (FORM, OTT, PASSKEY)
     */
    private Set<AuthType> enabledAuthTypes = EnumSet.of(AuthType.FORM);

    /**
     * JWT 등 외부 토큰 기반 인증 설정
     */
    @NestedConfigurationProperty
    private JwtsTokenSettings internal = new JwtsTokenSettings();

    /**
     * OAuth2 Resource Server 기반 자동 토큰 처리 (internal) 설정
     */
    @NestedConfigurationProperty
    private OAuth2TokenSettings oauth2 = new OAuth2TokenSettings();

    private long accessTokenValidity = 3600000;       // 1시간
    private long refreshTokenValidity = 604800000;    // 7일
    private long refreshRotateThreshold = 43200000; // 기본 12시간 (밀리초)

    private boolean enableRefreshToken = true;

    private String tokenPrefix = "Bearer ";
    private String rolesClaim = "roles";
    private String scopesClaim = "scopes";

    public boolean isAuthEnabled(AuthType type) {
        return enabledAuthTypes.contains(type);
    }

}

