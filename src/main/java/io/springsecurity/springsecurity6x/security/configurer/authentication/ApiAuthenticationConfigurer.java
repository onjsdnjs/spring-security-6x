package io.springsecurity.springsecurity6x.security.configurer.authentication;

import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.SessionStateStrategy;
import io.springsecurity.springsecurity6x.security.filter.ApiAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.handler.SecurityLogoutSuccessHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

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

        DelegatingSecurityContextRepository securityContextRepository = new DelegatingSecurityContextRepository(
                new RequestAttributeSecurityContextRepository(),
                new HttpSessionSecurityContextRepository());

        ApiAuthenticationFilter filter = new ApiAuthenticationFilter(loginProcessingUrl, securityContextRepository);

        filter.setAuthenticationManager(authenticationManager);
        http.logout(logout -> logout
                .logoutSuccessHandler(new SecurityLogoutSuccessHandler()));
        if(stateStrategy instanceof SessionStateStrategy){
            filter.session(true);
        }
        filter.setAuthenticationSuccessHandler(stateStrategy::onAuthenticationSuccess);

        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        http.setSharedObject(ApiAuthenticationFilter.class, filter);

    }
}
