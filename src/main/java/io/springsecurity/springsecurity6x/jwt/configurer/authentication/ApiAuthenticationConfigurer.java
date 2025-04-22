package io.springsecurity.springsecurity6x.jwt.configurer.authentication;

import io.springsecurity.springsecurity6x.jwt.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.jwt.filter.ApiAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class ApiAuthenticationConfigurer implements AuthenticationConfigurer {

    private String loginProcessingUrl = "/api/auth/login";
    private AuthenticationProvider authenticationProvider;
    private AuthenticationStateStrategy stateStrategy;
    private AuthenticationManager authenticationManager;

    public ApiAuthenticationConfigurer loginProcessingUrl(String url) {
        this.loginProcessingUrl = url;
        return this;
    }

    public ApiAuthenticationConfigurer authenticationProvider(AuthenticationProvider provider) {
        this.authenticationProvider = provider;
        return this;
    }

    public void authenticationManager(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void stateStrategy(AuthenticationStateStrategy strategy) {
        this.stateStrategy = strategy;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        ApiAuthenticationFilter filter = new ApiAuthenticationFilter(loginProcessingUrl);

        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationSuccessHandler(stateStrategy::onAuthenticationSuccess);

        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

    }
}
