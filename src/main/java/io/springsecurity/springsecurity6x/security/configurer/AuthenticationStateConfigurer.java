package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.SessionStateStrategy;
import io.springsecurity.springsecurity6x.security.filter.ApiAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtLogoutFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.function.Consumer;

public class AuthenticationStateConfigurer {

    private final HttpSecurity http;
    private AuthenticationStateStrategy stateStrategy = new SessionStateStrategy(); // default

    public AuthenticationStateConfigurer(HttpSecurity http) {
        this.http = http;
    }

    public AuthenticationStateConfigurer useJwt(Consumer<JwtStateStrategy> config) {
        JwtStateStrategy jwt = new JwtStateStrategy();
        this.stateStrategy = jwt;
        config.accept(jwt);
        http.addFilterAfter(new JwtAuthorizationFilter(jwt.tokenService()), ApiAuthenticationFilter.class);
        http.addFilterAfter(new JwtLogoutFilter(jwt.tokenService(),"/api/auth/logout"), JwtAuthorizationFilter.class);
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


