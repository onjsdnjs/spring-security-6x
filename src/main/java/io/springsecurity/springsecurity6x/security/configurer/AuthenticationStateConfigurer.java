package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.SessionStateStrategy;
import io.springsecurity.springsecurity6x.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.token.service.JwtsTokenProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class AuthenticationStateConfigurer {

    private final HttpSecurity http;
    private AuthenticationStateStrategy stateStrategy = new SessionStateStrategy(); // default

    public AuthenticationStateConfigurer(HttpSecurity http) {
        this.http = http;
    }

    public AuthenticationStateConfigurer useJwt(Customizer<JwtStateStrategy> config) {

        JwtStateStrategy jwt = new JwtStateStrategy();
        this.stateStrategy = jwt;
        config.customize(jwt);

        JwtsTokenProvider tokenService = (JwtsTokenProvider)jwt.tokenService();
        http.addFilterAfter(new JwtAuthorizationFilter(tokenService), ExceptionTranslationFilter.class);

        try {
            http.logout(logout -> logout
                    .addLogoutHandler(new TokenLogoutHandler(tokenService))
                    .logoutSuccessHandler(new TokenLogoutSuccessHandler()));

            http.exceptionHandling(exception -> exception
                    .authenticationEntryPoint(new TokenAuthenticationEntryPoint()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return this;
    }

    public AuthenticationStateConfigurer useSession() {
        this.stateStrategy = new SessionStateStrategy();
        return this;
    }

    public AuthenticationStateStrategy buildStrategy() {
        return stateStrategy;
    }
}


