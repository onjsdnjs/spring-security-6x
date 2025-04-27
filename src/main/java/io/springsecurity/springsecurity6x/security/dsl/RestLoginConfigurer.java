package io.springsecurity.springsecurity6x.security.dsl;

import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
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
    public void init(H http) throws Exception {

        super.init(http);

        /*RestAuthenticationFilter filter = getAuthenticationFilter();
        AuthenticationManager manager = http.getSharedObject(AuthenticationManager.class);

        if (manager != null) {
            filter.setAuthenticationManager(manager);
        }*/
    }

    @Override
    public void configure(H http) throws Exception {

        this.authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        this.authFilter.setAuthenticationSuccessHandler(this.successHandler);
        this.authFilter.setAuthenticationFailureHandler(this.failureHandler);
        if (this.authenticationDetailsSource != null) {
            this.authFilter.setAuthenticationDetailsSource(this.authenticationDetailsSource);
        }
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http
                .getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            this.authFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            this.authFilter.setRememberMeServices(rememberMeServices);
        }
        SecurityContextConfigurer securityContextConfigurer = http.getConfigurer(SecurityContextConfigurer.class);
        if (securityContextConfigurer != null && securityContextConfigurer.isRequireExplicitSave()) {
            SecurityContextRepository securityContextRepository = securityContextConfigurer
                    .getSecurityContextRepository();
            this.authFilter.setSecurityContextRepository(securityContextRepository);
        }
        this.authFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
        F filter = postProcess(this.authFilter);
        http.addFilter(filter);
    }
}

