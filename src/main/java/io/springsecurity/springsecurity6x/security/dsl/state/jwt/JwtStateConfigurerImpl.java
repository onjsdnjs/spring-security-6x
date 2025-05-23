package io.springsecurity.springsecurity6x.security.dsl.state.jwt;

import io.springsecurity.springsecurity6x.security.enums.TokenTransportType;
import io.springsecurity.springsecurity6x.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtPreAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtRefreshAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.authentication.JwtAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.logout.StrategyAwareLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.JwtTokenCreator;
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
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

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

        if(props.getTokenTransportType() == TokenTransportType.HEADER){
            http.csrf(AbstractHttpConfigurer::disable);
        }else{
            http.csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")));
        }

        http
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(e -> e
                    .authenticationEntryPoint(new TokenAuthenticationEntryPoint())
                    .accessDeniedHandler((request, response, exception) ->
                            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied")));
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        TokenParser parser = new JwtTokenParser(key);
        JwtTokenCreator tokenCreator = new JwtTokenCreator(key);
        RefreshTokenStore store = new JwtRefreshTokenStore(parser,props);
        TokenValidator validator = new JwtTokenValidator(parser, store, props.getRefreshRotateThreshold());
        TokenService tokenService = new JwtTokenService(validator, tokenCreator, store, transport, props);
        transport.setTokenService(tokenService);
        handlers  = new JwtAuthenticationHandlers(tokenService);

        http.logout(logout -> logout
                .logoutUrl("/api/auth/logout")
                .addLogoutHandler(handlers.logoutHandler())
                .logoutSuccessHandler(new StrategyAwareLogoutSuccessHandler()));

        http.addFilterAfter(new JwtAuthorizationFilter(tokenService, handlers.logoutHandler()), ExceptionTranslationFilter.class);
        http.addFilterAfter(new JwtRefreshAuthenticationFilter(tokenService, handlers.logoutHandler()), JwtAuthorizationFilter.class);
        http.addFilterBefore(new JwtPreAuthenticationFilter(tokenService), LogoutFilter.class);
    }
}