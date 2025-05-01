package io.springsecurity.springsecurity6x.security.dsl.state.session;

import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.authentication.DefaultAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * Session 기반 인증 상태 전략
 */
public class SessionStateConfigurerImpl extends AbstractHttpConfigurer<SessionStateConfigurerImpl, HttpSecurity> implements SessionStateConfigurer {

    private final AuthContextProperties properties;
    private final AuthenticationHandlers handlers;

    public SessionStateConfigurerImpl(AuthContextProperties properties) {
        this(properties, new DefaultAuthenticationHandlers());
    }

    public SessionStateConfigurerImpl(AuthContextProperties properties, AuthenticationHandlers handlers) {
        this.properties = properties;
        this.handlers = handlers;
    }

    public AuthenticationHandlers authHandlers() {
        return handlers;
    }

    @Override
    public void init(HttpSecurity http) {
        System.out.println("SessionStateConfigurerImpl.init()");
    }

    @Override
    public void configure(HttpSecurity http) {
        System.out.println("SessionStateConfigurerImpl.configure()");
    }

}
