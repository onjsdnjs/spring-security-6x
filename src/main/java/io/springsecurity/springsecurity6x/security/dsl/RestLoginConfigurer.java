package io.springsecurity.springsecurity6x.security.dsl;

import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class RestLoginConfigurer <H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, RestLoginConfigurer<H>, RestAuthenticationFilter> {

    public RestLoginConfigurer() {
        super(new RestAuthenticationFilter(), null);
    }

    @Override
    public RestLoginConfigurer<H> loginPage(String loginPage) {
        return super.loginPage(loginPage);
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }

    @Override
    public void init(H http) throws Exception {}

    @Override
    public void configure(H http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        RestAuthenticationFilter authFilter = new RestAuthenticationFilter(authenticationManager);
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http.getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            authFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            authFilter.setRememberMeServices(rememberMeServices);
        }
        SecurityContextConfigurer securityContextConfigurer = http.getConfigurer(SecurityContextConfigurer.class);
        if (securityContextConfigurer != null && securityContextConfigurer.isRequireExplicitSave()) {
            SecurityContextRepository securityContextRepository = securityContextConfigurer
                    .getSecurityContextRepository();
            authFilter.setSecurityContextRepository(securityContextRepository);
        }
        authFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
        http.addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class);
    }
}

