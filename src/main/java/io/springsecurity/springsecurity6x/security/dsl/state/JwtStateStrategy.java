package io.springsecurity.springsecurity6x.security.dsl.state;

import io.springsecurity.springsecurity6x.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtRefreshAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.handler.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.JwtAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.InternalJwtCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.InternalJwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.service.InternalJwtTokenService;
import io.springsecurity.springsecurity6x.security.token.store.InMemoryRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.HeaderTokenStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.validator.DefaultJwtTokenValidator;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.crypto.SecretKey;

public class JwtStateStrategy implements AuthenticationStateStrategy {

    private final TokenValidator validator;
    private final AuthenticationHandlers handlers;
    private final TokenTransportStrategy transportHandler;
    private final TokenCreator creator;
    private final RefreshTokenStore store;
    private final AuthContextProperties props;
    private final InternalJwtTokenService tokenService;
    private final JwtParser parser;

    public JwtStateStrategy(SecretKey key, AuthContextProperties props) {

        this.parser = new InternalJwtParser(key);
        this.props = props;
        this.creator = new InternalJwtCreator(key);
        this.store = new InMemoryRefreshTokenStore(parser);
        this.validator = new DefaultJwtTokenValidator(parser, store, props.getInternal().getRefreshRotateThreshold());
        this.tokenService = new InternalJwtTokenService(validator, creator, store, props);
        this.transportHandler = new HeaderTokenStrategy(); // 기본 Header
        this.handlers  = new JwtAuthenticationHandlers(tokenService, transportHandler, props);
    }

    public AuthenticationHandlers authHandlers() {
        return handlers;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        http
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new TokenAuthenticationEntryPoint())
                        .accessDeniedHandler((request, response, exception) ->
                                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied")))
                .logout(l -> l.addLogoutHandler(logoutHandler()));
        http.setSharedObject(AuthenticationHandlers.class, handlers);
    }

    @Override
    public void configure(HttpSecurity http) {
        http.addFilterAfter(new JwtAuthorizationFilter(tokenService, transportHandler, logoutHandler()), ExceptionTranslationFilter.class);
        http.addFilterAfter(new JwtRefreshAuthenticationFilter(tokenService, transportHandler, props), JwtAuthorizationFilter.class);
    }

    public LogoutHandler logoutHandler(){
        return new TokenLogoutHandler(validator);
    }
}





