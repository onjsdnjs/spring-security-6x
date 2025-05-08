package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.enums.StateType;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutHandler;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.function.Supplier;

import static org.springframework.security.config.Customizer.withDefaults;

public class CoreSecurityConfigurer implements SecurityConfigurer {

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) { }

    @Override
    public void configure(FlowContext fc) throws Exception {

        if (fc.flow().stateConfig() == null
                || !StateType.JWT.name().toLowerCase().equals(fc.flow().stateConfig().state())) {
            return;
        }

        HttpSecurity http = fc.http();

        Supplier<TokenService> logoutSupplier = () -> http.getSharedObject(TokenService.class);
        JwtLogoutHandler logoutHandler = new JwtLogoutHandler(logoutSupplier);
        JwtLogoutSuccessHandler successHandler = new JwtLogoutSuccessHandler();

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

    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}
