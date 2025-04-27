package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.handler.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.DefaultAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.JwtAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.InternalJwtCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.InternalJwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.store.InMemoryRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.HeaderTokenTransportHandler;
import io.springsecurity.springsecurity6x.security.token.validator.DefaultJwtTokenValidator;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import javax.crypto.SecretKey;

/**
 * Session 기반 인증 상태 전략
 */
public class SessionStateStrategy implements AuthenticationStateStrategy {

    private final AuthContextProperties properties;
    private final AuthenticationHandlers handlers;

    public SessionStateStrategy(AuthContextProperties properties) {
        this(properties, new DefaultAuthenticationHandlers());
    }

    public SessionStateStrategy(AuthContextProperties properties, AuthenticationHandlers handlers) {
        this.properties = properties;
        this.handlers = handlers;
    }

    public AuthenticationHandlers authHandlers() {
        return handlers;
    }

    @Override
    public void init(HttpSecurity http) { /* 기본 Spring Security 세션 흐름 그대로 */ }

    @Override
    public void configure(HttpSecurity http) { /* 필요 시 추가 세션 설정 */ }

}
