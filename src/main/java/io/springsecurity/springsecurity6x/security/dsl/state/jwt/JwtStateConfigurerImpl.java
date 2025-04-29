package io.springsecurity.springsecurity6x.security.dsl.state.jwt;

import io.springsecurity.springsecurity6x.security.enums.TokenTransportType;
import io.springsecurity.springsecurity6x.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtRefreshAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.authentication.JwtAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.JwtTokenCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.JwtTokenParser;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import io.springsecurity.springsecurity6x.security.token.service.JwtTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.JwtRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategyFactory;
import io.springsecurity.springsecurity6x.security.token.validator.JwtTokenValidator;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.ExceptionTranslationFilter;

import javax.crypto.SecretKey;

public class JwtStateConfigurerImpl implements JwtStateConfigurer {

    private final SecretKey key;
    private final AuthContextProperties props;
    private final TokenTransportStrategy transport;
    private AuthenticationHandlers handlers;

    public JwtStateConfigurerImpl(SecretKey key, AuthContextProperties props) {
        this.key = key;
        this.props = props;

        TokenTransportType transportType = props.getTokenTransportType();
        this.transport = TokenTransportStrategyFactory.create(transportType);
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
    }

    @Override
    public void configure(HttpSecurity http) {

        TokenParser parser = new JwtTokenParser(key);
        TokenCreator creator = new JwtTokenCreator(key);
        RefreshTokenStore store = new JwtRefreshTokenStore(parser);
        TokenValidator validator = new JwtTokenValidator(parser, store, props.getInternal().getRefreshRotateThreshold());
        TokenService tokenService = new JwtTokenService(validator, creator, store, transport, props);
        handlers  = new JwtAuthenticationHandlers(tokenService);

        http.addFilterAfter(new JwtAuthorizationFilter(tokenService, handlers.logoutHandler()), ExceptionTranslationFilter.class);
        http.addFilterAfter(new JwtRefreshAuthenticationFilter(tokenService, transport, props), JwtAuthorizationFilter.class);
    }
}