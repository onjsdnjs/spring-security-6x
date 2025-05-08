package io.springsecurity.springsecurity6x.security.core.feature.state.jwt;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutHandler;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.token.factory.JwtTokenServiceFactory;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.function.Supplier;

import static org.springframework.security.config.Customizer.withDefaults;

public class JwtStateFeature implements StateFeature {

    @Override
    public String getId() {
        return "jwt";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {

        TokenService service = JwtTokenServiceFactory.createService(ctx);
        JwtLogoutHandler logoutHandler = new JwtLogoutHandler(service);
        JwtLogoutSuccessHandler successHandler = new JwtLogoutSuccessHandler();

        http.setSharedObject(TokenService.class, service);
        http.setSharedObject(JwtLogoutHandler.class, logoutHandler);
        http.setSharedObject(JwtLogoutSuccessHandler.class, successHandler);

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

        http.with(new JwtStateConfigurer(), Customizer.withDefaults());

    }
}
