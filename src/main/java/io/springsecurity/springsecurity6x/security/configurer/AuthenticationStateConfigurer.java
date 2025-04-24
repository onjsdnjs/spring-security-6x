package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.SessionStateStrategy;
import io.springsecurity.springsecurity6x.security.filter.ApiAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.filter.JwtLogoutFilter;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.tokenservice.JwtsTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

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

        JwtsTokenService tokenService = (JwtsTokenService)jwt.tokenService();
        http.addFilterAfter(new JwtAuthorizationFilter(tokenService), ApiAuthenticationFilter.class);
        http.addFilterAfter(new JwtLogoutFilter(tokenService,"/api/auth/logout"), JwtAuthorizationFilter.class);

        try {
            http.logout(logout -> logout
                    .addLogoutHandler(new TokenLogoutHandler(tokenService.refreshTokenStore())));
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


