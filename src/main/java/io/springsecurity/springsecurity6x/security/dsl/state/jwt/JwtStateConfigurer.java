package io.springsecurity.springsecurity6x.security.dsl.state.jwt;

import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateConfigurer;
import io.springsecurity.springsecurity6x.security.enums.TokenTransportType;
import io.springsecurity.springsecurity6x.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtRefreshAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.handler.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.JwtAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.JwtCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.InternalJwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.service.InternalJwtTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.InMemoryRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategyFactory;
import io.springsecurity.springsecurity6x.security.token.validator.DefaultJwtTokenValidator;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.crypto.SecretKey;

public class JwtStateConfigurer implements AuthenticationStateConfigurer {

    private final SecretKey key;
    private final AuthContextProperties props;
    private final TokenTransportStrategy transport;
    private TokenService tokenService;
    private AuthenticationHandlers handlers;

    public JwtStateConfigurer(SecretKey key, AuthContextProperties props) {
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

        JwtParser parser = new InternalJwtParser(key);
        TokenCreator creator = new JwtCreator(key);
        RefreshTokenStore store = new InMemoryRefreshTokenStore(parser);
        TokenValidator validator = new DefaultJwtTokenValidator(parser, store, props.getInternal().getRefreshRotateThreshold());
        tokenService = new InternalJwtTokenService(validator, creator, store, props);
        handlers  = new JwtAuthenticationHandlers(tokenService, transport, props);

        http.addFilterAfter(new JwtAuthorizationFilter(tokenService, transport, logoutHandler()), ExceptionTranslationFilter.class);
        http.addFilterAfter(new JwtRefreshAuthenticationFilter(tokenService, transport, props), JwtAuthorizationFilter.class);
    }

    public LogoutHandler logoutHandler(){
        return new TokenLogoutHandler(tokenService);
    }
}





