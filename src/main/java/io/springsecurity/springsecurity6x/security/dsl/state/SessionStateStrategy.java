package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Session 기반 인증 상태 전략
 */
public class SessionStateStrategy implements AuthenticationStateStrategy {

    private final AuthContextProperties properties;

    public SessionStateStrategy(AuthContextProperties properties) {
        this.properties = properties;
    }

    @Override
    public void init(HttpSecurity http) { /* 기본 Spring Security 세션 흐름 그대로 */ }

    @Override
    public void configure(HttpSecurity http) { /* 필요 시 추가 세션 설정 */ }

}
