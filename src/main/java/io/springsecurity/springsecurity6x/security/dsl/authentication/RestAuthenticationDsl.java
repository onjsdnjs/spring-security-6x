package io.springsecurity.dsl;

import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.dsl.state.SessionStateStrategy;
import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

public final class RestAuthenticationDsl extends AbstractHttpConfigurer<RestAuthenticationDsl, HttpSecurity> {

    private String loginProcessingUrl = "/api/auth/login";
    private AuthenticationProvider authenticationProvider;
    private AuthenticationManager authenticationManager;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private AuthenticationStateStrategy stateStrategy;

    public RestAuthenticationDsl loginProcessingUrl(String url) {
        this.loginProcessingUrl = url;
        return this;
    }

    public RestAuthenticationDsl authenticationProvider(AuthenticationProvider provider) {
        this.authenticationProvider = provider;
        return this;
    }

    public RestAuthenticationDsl authenticationManager(AuthenticationManager manager) {
        this.authenticationManager = manager;
        return this;
    }

    public RestAuthenticationDsl successHandler(AuthenticationSuccessHandler handler) {
        this.successHandler = handler;
        return this;
    }

    public RestAuthenticationDsl failureHandler(AuthenticationFailureHandler handler) {
        this.failureHandler = handler;
        return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        this.stateStrategy = http.getSharedObject(AuthenticationStateStrategy.class);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        RestAuthenticationFilter filter = new RestAuthenticationFilter(
                loginProcessingUrl,
                new DelegatingSecurityContextRepository(
                        new RequestAttributeSecurityContextRepository(),
                        new HttpSessionSecurityContextRepository()
                )
        );
        filter.setAuthenticationManager(authenticationManager);

        if (successHandler != null) {
            filter.setAuthenticationSuccessHandler(successHandler);
        } else {
            filter.setAuthenticationSuccessHandler(stateStrategy.successHandler());
        }

        if (failureHandler != null) {
            filter.setAuthenticationFailureHandler(failureHandler);
        } else {
            filter.setAuthenticationFailureHandler(stateStrategy.failureHandler());
        }

        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }
}
