package io.springsecurity.springsecurity6x.jwt.configurer.authentication;

import io.springsecurity.springsecurity6x.jwt.filter.ApiAuthenticationFilter;
import io.springsecurity.springsecurity6x.jwt.configurer.state.AuthenticationStateStrategy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class ApiAuthenticationConfigurer extends AbstractHttpConfigurer<ApiAuthenticationConfigurer, HttpSecurity>  implements AuthenticationConfigurer {

    private String loginProcessingUrl = "/api/auth/login";
    private AuthenticationProvider authenticationProvider;
    private AuthenticationStateStrategy stateStrategy;

    public ApiAuthenticationConfigurer loginProcessingUrl(String url) {
        this.loginProcessingUrl = url;
        return this;
    }

    public ApiAuthenticationConfigurer authenticationProvider(AuthenticationProvider provider) {
        this.authenticationProvider = provider;
        return this;
    }

    @Override
    public void stateStrategy(AuthenticationStateStrategy strategy) {
        this.stateStrategy = strategy;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        ApiAuthenticationFilter filter = new ApiAuthenticationFilter(loginProcessingUrl);
        filter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        filter.setAuthenticationSuccessHandler(stateStrategy::onAuthenticationSuccess);

        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

        if (authenticationProvider != null) {
            http.authenticationProvider(authenticationProvider);
        }
    }
}
