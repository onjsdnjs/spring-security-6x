package io.springsecurity.springsecurity6x.security.core.feature.state.jwt;

import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtPreAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtRefreshAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.function.Supplier;

/**
 * JWT 상태 전략을 HttpSecurity에 적용하는 설정자
 */
public class JwtStateConfigurer extends AbstractHttpConfigurer<JwtStateConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) throws Exception {

        Supplier<LogoutHandler> logoutSupplier = () -> http.getSharedObject(LogoutHandler.class);

        /*LogoutConfigurer<HttpSecurity> logout = http.getConfigurer(LogoutConfigurer.class);
        if (logout == null) {
            http.with(new LogoutConfigurer<>(), Customizer.withDefaults());
        }

        http
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((req,res,ex) -> res.sendError(401))
                        .accessDeniedHandler((req,res,ex) -> res.sendError(403)))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(l -> l
                        .logoutRequestMatcher(new AntPathRequestMatcher("/api/auth/logout"))
                        .addLogoutHandler(logoutSupplier.get())
                        .logoutSuccessHandler(http.getSharedObject(LogoutSuccessHandler.class))
                );*/
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        TokenService service = http.getSharedObject(TokenService.class);
        Supplier<LogoutHandler> logoutSupplier = () -> http.getSharedObject(LogoutHandler.class);

        http.addFilterBefore(new JwtPreAuthenticationFilter(service), LogoutFilter.class);
        http.addFilterAfter(new JwtAuthorizationFilter(service, logoutSupplier), ExceptionTranslationFilter.class);
        http.addFilterAfter(new JwtRefreshAuthenticationFilter(service, logoutSupplier), JwtAuthorizationFilter.class);
    }
}

