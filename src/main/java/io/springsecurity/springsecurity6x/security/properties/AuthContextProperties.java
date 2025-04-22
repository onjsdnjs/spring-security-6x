package io.springsecurity.springsecurity6x.security.properties;

import io.springsecurity.springsecurity6x.security.enums.TokenControlMode;
import org.springframework.boot.context.properties.ConfigurationProperties;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.ContextMode;
import lombok.Data;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.stereotype.Component;

import java.util.EnumSet;
import java.util.Set;

@Data
@Component
@ConfigurationProperties(prefix = "spring.auth")
public class AuthContextProperties {

    /**
     * 인증 상태 유지 방식 선택 (JWT, SESSION, HYBRID 등)
     */
    private ContextMode contextMode = ContextMode.JWT;

    /**
     * 토큰 발급/검증의 주도권 설정
     */
    private TokenControlMode tokenControlMode = TokenControlMode.EXTERNAL;

    /**
     * 허용할 인증 방식 목록 (FORM, OTT, PASSKEY)
     */
    private Set<AuthType> enabledAuthTypes = EnumSet.of(AuthType.FORM);

    /**
     * JWT 등 외부 토큰 기반 인증 설정
     */
    @NestedConfigurationProperty
    private ExternalTokenSettings external = new ExternalTokenSettings();

    /**
     * OAuth2 Resource Server 기반 자동 토큰 처리 (internal) 설정
     */
    @NestedConfigurationProperty
    private InternalTokenSettings internal = new InternalTokenSettings();

    public boolean isAuthEnabled(AuthType type) {
        return enabledAuthTypes.contains(type);
    }

}

