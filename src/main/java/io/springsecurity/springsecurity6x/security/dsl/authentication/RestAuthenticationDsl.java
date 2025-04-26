package io.springsecurity.dsl;

import io.springsecurity.springsecurity6x.security.dsl.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.dsl.state.SessionStateStrategy;
import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

public final class RestAuthenticationDsl extends AbstractHttpConfigurer<RestAuthenticationDsl, HttpSecurity> {
    private String loginProcessingUrl = "/api/auth/login";
    private AuthenticationManager authenticationManager;

    public RestAuthenticationDsl loginProcessingUrl(String url) {
        this.loginProcessingUrl = url; return this;
    }
    public RestAuthenticationDsl authenticationManager(AuthenticationManager m) {
        this.authenticationManager = m; return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        AuthenticationStateStrategy s = http.getSharedObject(AuthenticationStateStrategy.class);
        RestAuthenticationFilter filter = new RestAuthenticationFilter(
                loginProcessingUrl,
                new DelegatingSecurityContextRepository(
                        new RequestAttributeSecurityContextRepository(),
                        new HttpSessionSecurityContextRepository()
                )
        );
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationSuccessHandler(s.successHandler());
        filter.setAuthenticationFailureHandler(s.failureHandler());
        filter.session(s instanceof SessionStateStrategy);
        http.setSharedObject(RestAuthenticationFilter.class, filter);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        RestAuthenticationFilter filter = http.getSharedObject(RestAuthenticationFilter.class);
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }
}
