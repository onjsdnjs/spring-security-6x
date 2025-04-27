package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.handler.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.JwtAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.InternalJwtCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.InternalJwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.store.InMemoryRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.validator.DefaultJwtTokenValidator;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportHandler;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import javax.crypto.SecretKey;

public class JwtStateStrategy implements AuthenticationStateStrategy {

    private final TokenCreator creator;
    private final TokenValidator validator;
    private final TokenTransportHandler transport;
    private final AuthenticationHandlers handlers;

    public JwtStateStrategy(SecretKey key,
                            AuthContextProperties props,
                            TokenTransportHandler transport) {
        JwtParser parser = new InternalJwtParser(key);
        var store      = new InMemoryRefreshTokenStore(parser);
        this.creator   = new InternalJwtCreator(key);
        this.validator = new DefaultJwtTokenValidator(parser, store, props.getInternal().getRefreshRotateThreshold());
        this.transport = transport;
        this.handlers  = new JwtAuthenticationHandlers(creator, transport, props);
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        http
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(handlers.entryPoint())
                        .accessDeniedHandler(handlers.accessDeniedHandler()))
                .logout(l -> l.addLogoutHandler(logoutHandler()));
        http.setSharedObject(AuthenticationHandlers.class, handlers);
    }

    @Override
    public void configure(HttpSecurity http) {
        http.addFilterAfter(
                new JwtAuthorizationFilter(validator, transport, logoutHandler()),
                ExceptionTranslationFilter.class);
    }

    @Override public AuthenticationSuccessHandler successHandler() { return handlers.successHandler(); }
    @Override public AuthenticationFailureHandler failureHandler() { return handlers.failureHandler(); }
    @Override public LogoutHandler logoutHandler()     { return new TokenLogoutHandler(validator); }
}





