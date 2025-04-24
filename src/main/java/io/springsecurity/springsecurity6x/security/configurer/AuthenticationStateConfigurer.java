package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.SessionStateStrategy;
import io.springsecurity.springsecurity6x.security.filter.ApiAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtLogoutFilter;
import io.springsecurity.springsecurity6x.security.handler.JwtLogoutHandler;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.function.Consumer;

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

        http.addFilterAfter(new JwtAuthorizationFilter(jwt.tokenService()), ApiAuthenticationFilter.class);
        http.addFilterAfter(new JwtLogoutFilter(jwt.tokenService(),"/api/auth/logout"), JwtAuthorizationFilter.class);

        try {
            http.logout(logout -> logout.addLogoutHandler(new JwtLogoutHandler()));
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


