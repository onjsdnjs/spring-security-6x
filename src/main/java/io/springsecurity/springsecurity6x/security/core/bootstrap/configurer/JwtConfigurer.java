package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import io.springsecurity.springsecurity6x.security.enums.TokenTransportType;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtPreAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtRefreshAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.authentication.JwtAuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutHandler;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutSuccessHandler;
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
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.crypto.SecretKey;

import static org.springframework.security.config.Customizer.withDefaults;

public class JwtConfigurer implements SecurityConfigurer {

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {}

    @Override
    public void configure(FlowContext fc) throws Exception {

        if (fc.flow().stateConfig() == null
                || !StateType.JWT.name().toLowerCase().equals(fc.flow().stateConfig().state())) {
            return;
        }

        HttpSecurity http = fc.http();


        SecretKey key = fc.context().getShared(SecretKey.class);
        AuthContextProperties props = fc.context().getShared(AuthContextProperties.class);
        TokenTransportType transportType = props.getTokenTransportType();
        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(transportType);

        TokenParser parser = new JwtTokenParser(key);
        JwtTokenCreator creator = new JwtTokenCreator(key);
        RefreshTokenStore store = new JwtRefreshTokenStore(parser, props);
        TokenValidator validator = new JwtTokenValidator(parser, store, props.getRefreshRotateThreshold());
        TokenService service = new JwtTokenService(validator, creator, store, transport, props);
        JwtLogoutHandler logoutHandler = new JwtLogoutHandler(service);
        JwtLogoutSuccessHandler successHandler = new JwtLogoutSuccessHandler();

        http.setSharedObject(TokenService.class, service);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((req, res, ex) ->
                                res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"))
                        .accessDeniedHandler((req, res, ex) ->
                                res.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied")))
                .headers(withDefaults())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/api/auth/logout"))
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler(successHandler));

        http.addFilterBefore(new JwtPreAuthenticationFilter(service), LogoutFilter.class);
        http.addFilterAfter(new JwtAuthorizationFilter(service, logoutHandler), ExceptionTranslationFilter.class);
        http.addFilterAfter(new JwtRefreshAuthenticationFilter(service, logoutHandler), JwtAuthorizationFilter.class);
}

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}